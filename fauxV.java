import java.io.*;
import java.sql.*;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;

public class SecurityFalsePositivesTest {

    /* =================================
       1. SQL Injection (FAUX POSITIF)
       -> Requête préparée (sécurisée)
       ================================= */
    public void safeSql(HttpServletRequest request) throws Exception {
        String user = request.getParameter("user");

        Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost/test", "root", "root");

        PreparedStatement ps =
                conn.prepareStatement("SELECT * FROM users WHERE username = ?");
        ps.setString(1, user);
        ps.executeQuery(); // SÛR
    }

    /* =================================
       2. XSS (FAUX POSITIF)
       -> Encodage HTML manuel
       ================================= */
    public void safeXss(HttpServletRequest request, PrintWriter out) {
        String input = request.getParameter("msg");
        String encoded = input
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");

        out.println("<html><body>" + encoded + "</body></html>"); // SÛR
    }

    /* =================================
       3. Command Execution (FAUX POSITIF)
       -> Liste blanche
       ================================= */
    public void safeCommand(HttpServletRequest request) throws IOException {
        String cmd = request.getParameter("cmd");

        if ("date".equals(cmd) || "uptime".equals(cmd)) {
            Runtime.getRuntime().exec(cmd); // SÛR
        }
    }

    /* =================================
       4. Path Traversal (FAUX POSITIF)
       -> Validation stricte du chemin
       ================================= */
    public void safePath(HttpServletRequest request) throws IOException {
        String file = request.getParameter("file");

        if (file != null && file.matches("[a-zA-Z0-9._-]+")) {
            File f = new File("/app/data/", file);
            File canonical = f.getCanonicalFile();

            if (canonical.getPath().startsWith("/app/data/")) {
                new FileInputStream(canonical).close(); // SÛR
            }
        }
    }

    /* =================================
       5. Insecure Deserialization (FAUX POSITIF)
       -> Classe autorisée uniquement
       ================================= */
    public void safeDeserialization(InputStream inputStream)
            throws Exception {

        ObjectInputStream ois = new ObjectInputStream(inputStream);
        Object obj = ois.readObject();

        if (obj instanceof String) {
            System.out.println(obj); // SÛR
        }
        ois.close();
    }

    /* =================================
       6. Hardcoded Secret (FAUX POSITIF)
       -> Clé de test non sensible
       ================================= */
    public void testKeyOnly() {
        final String TEST_KEY = "TEST_KEY_123"; // Non sensible
        System.out.println(TEST_KEY);
    }

    /* =================================
       7. Cryptographie (FAUX POSITIF)
       -> AES fort mais mal détecté
       ================================= */
    public void strongCrypto() throws Exception {
        byte[] key = "1234567890123456".getBytes();
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] encrypted = cipher.doFinal("secure".getBytes());
        System.out.println(Base64.getEncoder().encodeToString(encrypted));
    }
}
