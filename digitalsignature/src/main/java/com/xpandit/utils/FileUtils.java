package com.xpandit.utils;

import java.io.File;

/**
 * Description
 *
 * @author <a href="mailto:ricardo.vieira@xpand-it.com">RJSV</a>
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

}
