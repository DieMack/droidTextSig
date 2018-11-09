package rjsvieira.digitalsignature.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Description
 *
 * @author <a href="mailto:rvfts@hotmail.com">RJSV</a>
 * @version $Revision : 1 $
 */

public class FileUtils {

    public static Boolean fileExists(String path) {
        Boolean result = false;
        File file = new File(path);
        if (file.exists())
            result = true;
        return result;
    }

    public static void copyFile(String inputFile, String outputFile) throws IOException {
        InputStream in = null;
        OutputStream out = null;

        in = new FileInputStream(inputFile);
        out = new FileOutputStream(outputFile);

        byte[] buffer = new byte[1024];
        int read;
        while ((read = in.read(buffer)) != -1) {
            out.write(buffer, 0, read);
        }
        in.close();
        in = null;

        // write the output file
        out.flush();
        out.close();
        out = null;
    }

    public static void moveFile(String inputFile, String outputPath) throws IOException {
        InputStream in = null;
        OutputStream out = null;
        //create output directory if it doesn't exist
        File dir = new File(outputPath);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        in = new FileInputStream(inputFile);
        out = new FileOutputStream(outputPath + inputFile);
        byte[] buffer = new byte[1024];
        int read;
        while ((read = in.read(buffer)) != -1) {
            out.write(buffer, 0, read);
        }
        in.close();
        in = null;
        // write the output file
        out.flush();
        out.close();
        out = null;
        // delete the original file
        new File(inputFile).delete();
    }

    public static void deleteFile(String inputFile) throws IOException {
        new File(inputFile).delete();
    }

    public static boolean renameFile(String directory, String oldFileName, String newFileName) {
        File from = new File(directory, oldFileName);
        File to = new File(directory, newFileName);
        return from.renameTo(to);
    }

    public static boolean renameFile(String oldFileName, String newFileName) {
        File from = new File(oldFileName);
        File to = new File(newFileName);
        return from.renameTo(to);
    }
}
