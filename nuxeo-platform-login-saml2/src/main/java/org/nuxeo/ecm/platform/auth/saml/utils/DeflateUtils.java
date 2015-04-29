package org.nuxeo.ecm.platform.auth.saml.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;

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
    

    public static byte[] decompress(byte[] data) throws IOException, DataFormatException {
        Inflater inflater = new Inflater(true);
        inflater.setInput(data);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
        byte[] buffer = new byte[1024];
        while (!inflater.finished()) {
            int count = inflater.inflate(buffer);
            outputStream.write(buffer, 0, count);
        }
        outputStream.close();
        byte[] output = outputStream.toByteArray();

        return output;
    }
}
