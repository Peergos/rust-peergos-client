import peergos.server.Builder;
import peergos.shared.Crypto;
import peergos.shared.NetworkAccess;
import peergos.shared.crypto.hash.Blake3;
import peergos.shared.login.mfa.MultiFactorAuthMethod;
import peergos.shared.login.mfa.MultiFactorAuthResponse;
import peergos.shared.social.FollowRequestWithCipherText;
import peergos.shared.crypto.symmetric.SymmetricKey;
import peergos.shared.user.*;
import peergos.shared.user.fs.*;
import peergos.shared.user.fs.archive.*;
import peergos.shared.util.*;

import java.net.URL;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;

/** Java half of the interop run: checks what the Rust client wrote, and writes things for it to check. */
public class Interop {
    static NetworkAccess network;
    static Crypto crypto;
    static Path dir;

    public static void main(String[] args) throws Exception {
        peergos.server.util.JavaInflate.init();
        crypto = Builder.initCrypto();
        network = Builder.buildJavaNetworkAccess(new URL("http://localhost:7777"), false, Optional.empty(), Optional.empty()).join();
        dir = Paths.get(args[1]);
        switch (args[0]) {
            case "check-rust" -> checkRust();
            case "java-setup" -> javaSetup();
            case "befriend" -> befriend();
            case "java-share" -> javaShare();
            case "check-rust-wrote" -> checkRustWrote();
            case "mfa-login" -> mfaLogin();
            default -> throw new IllegalStateException("unknown step " + args[0]);
        }
        System.exit(0);
    }

    static void check(boolean ok, String what) {
        if (! ok)
            throw new IllegalStateException("FAIL " + what);
        System.out.println("  ok   " + what);
    }

    static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b)
            s.append(String.format("%02x", x & 0xff));
        return s.toString();
    }

    static String sha(byte[] b) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(b));
    }

    static byte[] readAll(AsyncReader r, long size) {
        byte[] res = new byte[(int) size];
        int done = 0;
        while (done < size) {
            int n = r.readIntoArray(res, done, (int) size - done).join();
            if (n <= 0)
                throw new IllegalStateException("short read");
            done += n;
        }
        return res;
    }

    static byte[] read(FileWrapper f) {
        return readAll(f.getInputStream(network, crypto, x -> {}).join(), f.getSize());
    }

    static FileWrapper get(UserContext ctx, String path) {
        return ctx.getByPath(path).join().orElseThrow(() -> new IllegalStateException("missing " + path));
    }

    static UserContext signIn(String user, String pw) {
        return UserContext.signIn(user, pw, req -> Futures.errored(new IllegalStateException("unexpected mfa")), network, crypto).join();
    }

    static UserContext signUpOrIn(String user, String pw) {
        try {
            return UserContext.signUp(user, pw, "", network, crypto).join();
        } catch (Exception e) {
            return signIn(user, pw);
        }
    }

    static FileWrapper upload(FileWrapper dir, String name, byte[] data) {
        return dir.uploadOrReplaceFile(name, AsyncReader.build(data), 0, data.length, network, crypto, x -> {}).join();
    }

    static FileWrapper mkdirIfAbsent(UserContext ctx, String parentPath, String name) {
        FileWrapper parent = get(ctx, parentPath);
        Optional<FileWrapper> existing = parent.getChild(name, crypto.hasher, network).join();
        if (existing.isPresent())
            return existing.get();
        parent.mkdir(name, network, false, Optional.empty(), crypto).join();
        return get(ctx, parentPath + "/" + name);
    }

    static byte[] pattern(int len, int seed) {
        byte[] b = new byte[len];
        for (int i = 0; i < len; i++)
            b[i] = (byte) (i * 31 + seed);
        return b;
    }

    static void checkRust() throws Exception {
        UserContext ri = signIn("ri", "ripass");
        for (String line : Files.readAllLines(dir.resolve("rust-expected.txt"))) {
            String[] parts = line.split(" ");
            check(sha(read(get(ri, parts[0]))).equals(parts[1]), parts[0] + " reads as the Rust client wrote it");
        }
        // the 4 MiB chunk file carries its chunk size and a BLAKE3 root
        FileWrapper b3 = get(ri, "/ri/interop/b3.bin");
        FileProperties props = b3.getFileProperties();
        check(props.chunkSize == Chunk.DEFAULT_SIZE, "b3.bin has the 4 MiB chunk size: " + props.chunkSize);
        String blake3 = Files.readString(dir.resolve("b3.blake3")).trim();
        check(hex(Blake3.hash(read(b3))).equals(blake3), "b3.bin's content hashes to the recorded BLAKE3");
        check(hex(props.treeHash.get().rootHash.hash).equals(blake3), "b3.bin's stored root is its BLAKE3 hash");

        // the zip the Rust client edited
        ZipReader zip = ZipReader.open(get(ri, "/ri/interop/archive.zip"), network, crypto).join();
        ZipEntry added = zip.getIndex().get("rust/added.txt").get();
        check(new String(readAll(zip.read(added).join(), added.size)).equals("added by the rust client"), "Rust-added zip entry reads in Java");
        ZipEntry readme = zip.getIndex().get("README.txt").get();
        check(readAll(zip.read(readme).join(), readme.size).length == 500, "Rust-renamed zip entry reads in Java");
        check(zip.getIndex().get("readme.txt").isEmpty() && zip.getIndex().get("empty").isEmpty(), "Rust-removed zip entries are gone");

        // the owner's view of the Rust link
        List<SecretLinkSummary> links = ri.getAllSecretLinks().join();
        String link = Files.readString(dir.resolve("rust-link.txt")).trim();
        SecretLinkSummary summary = links.stream().filter(s -> link.contains(s.linkString(ri.signer.publicKeyHash)))
                .findFirst().orElseThrow(() -> new IllegalStateException("Rust link not listed: " + links.size() + " links"));
        check(Arrays.asList(summary.paths()).equals(List.of("/ri/interop/small.txt", "/ri/interop/bulk")), "Java lists the Rust link's members: " + Arrays.toString(summary.paths()));
        check(summary.isWritable(), "Java sees the Rust link as writable");
        List<LinkMember> members = ri.getSecretLinkMembers(summary.props).join();
        check(members.size() == 2 && ! members.get(0).writable && members.get(1).writable, "Java reads the Rust link's payload");

        // open it as anyone with the link
        UserContext anon = UserContext.fromSecretLinkV2(link, () -> Futures.of(""), network, crypto).join();
        check(new String(read(get(anon, "/ri/interop/small.txt"))).equals("written by the rust client"), "Java opens the Rust link's read-only item");
        FileWrapper bulk = get(anon, "/ri/interop/bulk");
        check(bulk.isWritable(), "the Rust link's folder is writable in Java");
        upload(bulk, "via-rust-link.txt", "java wrote through a rust link".getBytes());
        System.out.println("check-rust done");
    }

    static void javaSetup() throws Exception {
        UserContext ji = signUpOrIn("ji", "jipass");
        FileWrapper root = mkdirIfAbsent(ji, "/ji", "jinterop");
        List<String> expected = new ArrayList<>();
        byte[] small = "written by the java client".getBytes();
        upload(root, "j-small.txt", small);
        expected.add("/ji/jinterop/j-small.txt " + sha(small));
        byte[] big = pattern(7 * 1024 * 1024 + 11, 4);
        upload(get(ji, "/ji/jinterop"), "j-big.bin", big);
        expected.add("/ji/jinterop/j-big.bin " + sha(big));
        mkdirIfAbsent(ji, "/ji/jinterop", "jlinkdir");
        mkdirIfAbsent(ji, "/ji/jinterop", "jshared");

        // a zip built with the Java ZipWriter, starting from an empty archive
        byte[] emptyZip = new byte[22];
        emptyZip[0] = 0x50; emptyZip[1] = 0x4b; emptyZip[2] = 0x05; emptyZip[3] = 0x06;
        upload(get(ji, "/ji/jinterop"), "java.zip", emptyZip);
        byte[] zipped = "zipped by the java client".getBytes();
        ZipWriter.NewEntry entry = new ZipWriter.NewEntry("docs/j.txt", zipped.length, LocalDateTime.now(),
                () -> Futures.of(AsyncReader.build(zipped)));
        ZipWriter.append(get(ji, "/ji/jinterop/java.zip"), List.of(entry), network, crypto, x -> {}).join();

        LinkProperties props = ji.createSecretLink(List.of("/ji/jinterop/j-small.txt", "/ji/jinterop/jlinkdir"),
                List.of("/ji/jinterop/jlinkdir"), Optional.empty(), Optional.empty(), "", false).join();
        Files.writeString(dir.resolve("java-link.txt"), ji.getLinkString(props));
        Files.writeString(dir.resolve("java-expected.txt"), String.join("\n", expected));
        System.out.println("java-setup done");
    }

    static void befriend() {
        UserContext ji = signIn("ji", "jipass");
        UserContext ri = signIn("ri", "ripass");
        ji.sendFollowRequest("ri", SymmetricKey.random()).join();
        for (FollowRequestWithCipherText req : ri.processFollowRequests().join())
            ri.sendReplyFollowRequest(req, true, true).join();
        ji.processFollowRequests().join();
        System.out.println("befriend done");
    }

    static void javaShare() {
        UserContext ji = signIn("ji", "jipass");
        ji.shareWriteAccessWith(Paths.get("/ji/jinterop/jshared"), Set.of("ri")).join();
        // write into the folder the Rust user shared with us
        FileWrapper shared = get(ji, "/ri/interop/shared");
        check(shared.isWritable(), "Rust's write share is writable in Java");
        upload(shared, "from-java.txt", "java wrote into rust's shared folder".getBytes());
        System.out.println("java-share done");
    }

    static void checkRustWrote() {
        UserContext ji = signIn("ji", "jipass");
        check(new String(read(get(ji, "/ji/jinterop/jshared/from-rust.txt"))).equals("rust wrote into java's shared folder"), "Rust wrote into Java's write share");
        check(new String(read(get(ji, "/ji/jinterop/jlinkdir/via-java-link.txt"))).equals("rust wrote through a java link"), "Java reads what Rust wrote through its link");
        System.out.println("check-rust-wrote done");
    }

    static void mfaLogin() throws Exception {
        String code = Files.readAllLines(dir.resolve("backup-codes.txt")).get(0);
        UserContext rm = UserContext.signIn("rm", "rmpass", req -> {
            MultiFactorAuthMethod m = req.methods.stream().filter(x -> x.type == MultiFactorAuthMethod.Type.BACKUP_CODES)
                    .findFirst().orElseThrow(() -> new IllegalStateException("no backup codes offered"));
            return Futures.of(new MultiFactorAuthResponse(m.credentialId, Either.a(code)));
        }, network, crypto).join();
        check(rm.username.equals("rm"), "Java signs in with a backup code the Rust client generated");
        System.out.println("mfa-login done");
    }
}
