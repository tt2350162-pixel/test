import java.io.*;
import java.sql.*;
import javax.servlet.http.HttpServletRequest;

public class SecurityScannerTest {

    /* ============================
       1. SQL Injection
       ============================ */
    public void sqlInjection(HttpServletRequest request) throws Exception {
        String user = request.getParameter("user");
        Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost/test", "root", "root");

        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE username = '" + user + "'";
        stmt.executeQuery(query); // Vulnérable
    }

    /* ============================
       2. Cross-Site Scripting (XSS)
       ============================ */
    public void xss(HttpServletRequest request, PrintWriter out) {
        String msg = request.getParameter("msg");
        out.println("<html><body>" + msg + "</body></html>"); // Vulnérable
    }

    /* ============================
       3. Command Injection
       ============================ */
    public void commandInjection(HttpServletRequest request) throws IOException {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec(cmd); // Vulnérable
    }

    /* ============================
       4. Path Traversal
       ============================ */
    public void pathTraversal(HttpServletRequest request) throws IOException {
        String file = request.getParameter("file");
        FileInputStream fis = new FileInputStream("/app/data/" + file); // Vulnérable
        fis.close();
    }

    /* ============================
       5. Insecure Deserialization
       ============================ */
    public void insecureDeserialization(InputStream inputStream)
            throws IOException, ClassNotFoundException {

        ObjectInputStream ois = new ObjectInputStream(inputStream);
        Object obj = ois.readObject(); // Vulnérable
        ois.close();
    }

    /* ============================
       6. Hardcoded Credentials
       ============================ */
    public void hardcodedPassword() {
        String username = "admin";
        String password = "P@ssw0rd123"; // Vulnérable
        System.out.println(username + password);
    }

    /* ============================
       7. Weak Cryptography
       ============================ */
    public void weakCrypto() throws Exception {
        String data = "secret";
        java.security.MessageDigest md =
                java.security.MessageDigest.getInstance("MD5"); // Vulnérable
        md.update(data.getBytes());
        md.digest();
    }
}
