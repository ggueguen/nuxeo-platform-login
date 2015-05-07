package org.nuxeo.ecm.platform.auth.saml.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

public class DeflateUtils {
    
    public static byte[] compress(byte[] data) throws IOException {

        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);

        DeflaterOutputStream defOut = new DeflaterOutputStream(outputStream, deflater);
        defOut.write(data);
        defOut.close();

        deflater.finish();
        outputStream.close();

        return outputStream.toByteArray();
    }
    


}
