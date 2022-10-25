package com.suriya.license.io;

public final class Info implements BaseProductKey {

    private String filePath;
    private String fileName;
    private String filePassword;

    private String productName;
    private String productPassword;

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public String getFilePassword() {
        return filePassword;
    }

    public void setFilePassword(String filePassword) {
        this.filePassword = filePassword;
    }

    public String getProductName() {
        return productName;
    }

    public void setProductName(String productName) {
        this.productName = productName;
    }

    public String getProductPassword() {
        return productPassword;
    }

    public void setProductPassword(String productPassword) {
        this.productPassword = productPassword;
    }

}
