package com.suriya.keychain.core.parser;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static com.suriya.keychain.io.Settings.ContentFormat.*;

public class Content {

    // CAPACITY
    //////// 4 byte
    //////// 8 byte
    //////// x byte

//    static int determinedHeaderLengthStoreByteCapacity = 4;
//    static int headerByteCapacity = 256;

    public enum Type {
        HEADER,
        BODY;
    }

    public static byte[] encode(byte[] header, byte[] body) {
        byte[] allByteArray = new byte[determinedHeaderLengthStoreByteCapacity + headerByteCapacity + body.length];
        ByteBuffer buff = ByteBuffer.wrap(allByteArray);
        buff.putInt(header.length);
        buff.put(new byte[determinedHeaderLengthStoreByteCapacity - buff.position()]);
        buff.put(header);
        buff.put(new byte[(headerByteCapacity + determinedHeaderLengthStoreByteCapacity) - buff.position()]);
        buff.put(body);
        return buff.array();
    }


    public static byte[] decode(byte[] computed, Type type) {
        byte[] byteArray = null;
        byte[] headerLengthByteArray = Arrays.copyOfRange(computed, 0 , determinedHeaderLengthStoreByteCapacity);
        int headerActualSize = ByteBuffer.wrap(headerLengthByteArray).getInt();
        if (type.equals(Type.HEADER)) {
            byteArray = Arrays.copyOfRange(computed, determinedHeaderLengthStoreByteCapacity, determinedHeaderLengthStoreByteCapacity + headerActualSize);
        } else if (type.equals(Type.BODY)) {
            byteArray = Arrays.copyOfRange(computed, headerByteCapacity + determinedHeaderLengthStoreByteCapacity, computed.length);
        }
        return byteArray;
    }

}
