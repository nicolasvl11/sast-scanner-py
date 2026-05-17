package com.example.vulnerable;

import java.io.*;
import java.sql.*;

// This file is intentionally vulnerable — used as a test fixture for the SAST scanner.
// DO NOT use this code in production.
public class VulnerableService {

    // SQLI-001: SQL injection via string concatenation
    public void getUserByName(Connection conn, String username) throws SQLException {
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);
    }

    // SEC-001: Hardcoded password
    private static final String DB_PASSWORD = "supersecret123";

    // SEC-002: Hardcoded API key
    private static final String API_KEY = "sk-live-abc123XYZ789secretkey";

    // CMD-001: OS command injection
    public void runReport(String reportName) throws IOException {
        Runtime.getRuntime().exec("generate-report.sh " + reportName);
    }

    // DESER-001: Unsafe deserialization
    public Object deserialize(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }

    // PATH-001: Path traversal
    public String readFile(HttpServletRequest request) throws IOException {
        String filename = request.getParameter("file");
        File file = new File("/var/data/" + filename);
        return new String(java.nio.file.Files.readAllBytes(file.toPath()));
    }

    // PATH-003: File upload with original filename
    public void saveUpload(MultipartFile file) throws IOException {
        String filename = file.getOriginalFilename();
        file.transferTo(new File("/uploads/" + filename));
    }
}
