import javax.net.ssl.*;
import java.io.FileInputStream;
import java.nio.*;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Iterator;

public class TLSServer {

    private static final int PORT = 9000;

    // Protocol constants
    private static final int HEADER_SIZE = 1 + 4;

    public static void main(String[] args) throws Exception {
        // ----------------------------
        // Load key store
        // ----------------------------
        char[] pass = FILL_IN

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream("server.jks"), pass);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, pass);

        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(kmf.getKeyManagers(), null, null);

        // ----------------------------
        // Setup server socket channel
        // ----------------------------
        ServerSocketChannel server = ServerSocketChannel.open();
        server.configureBlocking(false);
        server.bind(new java.net.InetSocketAddress(PORT));

        Selector selector = Selector.open();
        server.register(selector, SelectionKey.OP_ACCEPT);

        System.out.println("TLS NIO server running on port " + PORT);

        // ----------------------------
        // Event loop
        // ----------------------------
        while (true) {
            selector.select();

            Iterator<SelectionKey> iter = selector.selectedKeys().iterator();
            while (iter.hasNext()) {
                SelectionKey key = iter.next();
                iter.remove();

                try {
                    if (key.isAcceptable()) {
                        handleAccept(key, ssl, selector);
                    } else {
                        Connection conn = (Connection) key.attachment();

                        if (key.isReadable()) {
                            conn.doRead();
                        }
                        if (key.isWritable()) {
                            conn.doWrite();
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    key.cancel();
                }
            }
        }
    }

    // ==========================
    // Accept new connection
    // ==========================
    private static void handleAccept(SelectionKey key, SSLContext ssl, Selector selector) throws Exception {
        ServerSocketChannel server = (ServerSocketChannel) key.channel();
        SocketChannel sc = server.accept();
        sc.configureBlocking(false);

        SSLEngine engine = ssl.createSSLEngine();
        engine.setUseClientMode(false);
        engine.beginHandshake();

        Connection conn = new Connection(sc, engine, selector);
        sc.register(selector, SelectionKey.OP_READ, conn);

        System.out.println("Accepted new TLS connection");
    }

    // ============================================================================
    // Connection class: handles TLS wrapping/unwrapping & protocol decoding
    // ============================================================================
    private static class Connection {

        private final SocketChannel channel;
        private final SSLEngine engine;
        private final Selector selector;

        // TLS buffers
        private final ByteBuffer netIn;
        private final ByteBuffer netOut;
        private final ByteBuffer appIn;
        private final ByteBuffer appOut;

        // Protocol state
        private boolean readingHeader = true;
        private byte msgId;
        private int length;

        Connection(SocketChannel ch, SSLEngine eng, Selector sel) {
            this.channel = ch;
            this.engine = eng;
            this.selector = sel;

            SSLSession session = eng.getSession();

            this.netIn = ByteBuffer.allocate(session.getPacketBufferSize());
            this.netOut = ByteBuffer.allocate(session.getPacketBufferSize());
            this.appIn = ByteBuffer.allocate(session.getApplicationBufferSize());
            this.appOut = ByteBuffer.allocate(session.getApplicationBufferSize());

            netIn.flip();   // ready for reading
            netOut.flip();
        }

        // ===========================================
        //  READ side
        // ===========================================
        void doRead() throws Exception {
            // Move unread bytes down
            netIn.compact();
            int read = channel.read(netIn);
            netIn.flip();

            if (read == -1) {
                close();
                return;
            }

            // unwrap TLS → plaintext
            unwrapLoop();

            // parse protocol messages from appIn
            parseMessages();
        }

        private void parseMessages() throws Exception {
            while (true) {
                if (readingHeader) {
                    if (appIn.remaining() < HEADER_SIZE)
                        return;

                    msgId = appIn.get();
                    length = appIn.getInt();

                    readingHeader = false;
                }

                if (appIn.remaining() < length)
                    return;

                byte[] payload = new byte[length];
                appIn.get(payload);

                // ---- Your protocol logic here ----
                System.out.println("Received msgId=" + msgId + " payload=" + new String(payload));

                // Build reply: simply echo with msgId+1
                String replyText = "SERVER ECHO: " + new String(payload);
                byte[] replyBytes = replyText.getBytes(StandardCharsets.UTF_8);

                ByteBuffer msg = ByteBuffer.allocate(HEADER_SIZE + replyBytes.length);
                msg.put((byte) (msgId + 1));
                msg.putInt(replyBytes.length);
                msg.put(replyBytes);
                msg.flip();

                send(msg);

                readingHeader = true;
            }
        }

        // ===========================================
        //  WRITE side
        // ===========================================
        void doWrite() throws Exception {
            netOut.flip();
            channel.write(netOut);
            netOut.compact();
        }

        private void send(ByteBuffer plain) throws Exception {
            while (plain.hasRemaining()) {
                SSLEngineResult res = engine.wrap(plain, netOut);
                if (res.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                    netOut.compact();
                    netOut.flip();
                }
            }
            channel.keyFor(selector).interestOps(SelectionKey.OP_READ | SelectionKey.OP_WRITE);
        }

        // ===========================================
        // TLS unwrap
        // ===========================================
        private void unwrapLoop() throws Exception {
            while (netIn.hasRemaining()) {
                SSLEngineResult res = engine.unwrap(netIn, appIn);

                switch (res.getStatus()) {
                    case BUFFER_OVERFLOW:
                        appIn.compact();
                        appIn.position(appIn.limit());
                        appIn.limit(appIn.capacity());
                        break;

                    case BUFFER_UNDERFLOW:
                        return;

                    case CLOSED:
                        close();
                        return;

                    default:
                        break;
                }
            }

            appIn.flip();
        }

        private void close() throws Exception {
            channel.close();
        }
    }
}
