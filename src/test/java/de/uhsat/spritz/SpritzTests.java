/*
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org>
 */
package de.uhsat.spritz;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

public final class SpritzTests {
    /**
     * Tests the build-in encryption feature.
     */
    @Test
    public void testEncryption() {
        var key = getShorts("Secret");
        var pt = getShorts("Hello World!");
        var ct = pt.clone();

        Spritz.encrypt(ct, key);
        Spritz.decrypt(ct, key);

        IntStream.range(0, pt.length).forEach(i -> assertEquals(pt[i], ct[i]));
    }

    /**
     * Tests the build-in encryption feature.
     */
    @Test
    public void testEncryptionWithIV() {
        var key = getShorts("Secret");
        var iv = getShorts("Vector");
        var pt = getShorts("Hello World!");
        var ct = pt.clone();

        Spritz.encrypt(ct, key, iv);
        Spritz.decrypt(ct, key, iv);

        IntStream.range(0, pt.length).forEach(i -> assertEquals(pt[i], ct[i]));
    }

    /**
     * Tests the build-in pseudo random number feature.
     */
    @Test
    public void testRandom() {
        Spritz.randomSeed(getShorts("Seed"));

        var number = Spritz.random();

        assertNotEquals(0, number);
    }

    /**
     * Tests the build-in message authentication feature.
     */
    @Test
    public void testMac(){
        var key = getShorts("Secret");
        var msg = getShorts("Hello World!");
        var test = new short[] { 0x8D, 0xA4, 0x44, 0xD8, 0xF5, 0x77, 0xC4, 0x11 };
        var code = new short[8];

        Spritz.mac(msg, key, code);

        IntStream.range(0, code.length).forEach(i -> assertEquals(test[i], code[i]));
    }

    /**
     * Tests all official basic test vectors (from APPENDIX E).
     */
    @Test
    public void testBasic() {
        var inputs = new String[] { "ABC", "spam", "arcfour" };

        var outputs  = new short[][] {
                { 0x77, 0x9A, 0x8E, 0x01, 0xF9, 0xE9, 0xCB, 0xC0 },
                { 0xF0, 0x60, 0x9A, 0x1D, 0xF1, 0x43, 0xCE, 0xBF },
                { 0x1A, 0xFA, 0x8B, 0x5E, 0xE3, 0x37, 0xDB, 0xC7 }
        };

        for (int test = 0; test < 3; test++) {
            var input = getShorts(inputs[test]);
            var vector = outputs[test];
            var output = new short[8];

            Spritz.basic(input, output);

            IntStream.range(0, vector.length).forEach(i -> assertEquals(vector[i], output[i]));
        }
    }

    /**
     * Tests all official hash test vectors (from APPENDIX E).
     */
    @Test
    public void testHash() {
        var inputs = new String[] { "ABC", "spam", "arcfour" };

        var outputs  = new short[][] {
                { 0x02, 0x8F, 0xA2, 0xB4, 0x8B, 0x93, 0x4A, 0x18 },
                { 0xAC, 0xBB, 0xA0, 0x81, 0x3F, 0x30, 0x0D, 0x3A },
                { 0xFF, 0x8C, 0xF2, 0x68, 0x09, 0x4C, 0x87, 0xB9 }
        };

        for (int test = 0; test < 3; test++) {
            var message = getShorts(inputs[test]);
            var vector = outputs[test];
            var digest = new short[32];

            Spritz.hash(message, digest);

            IntStream.range(0, vector.length).forEach(i -> assertEquals(vector[i], digest[i]));
        }
    }

    /**
     * Returns the given strings bytes as shorts.
     * @param input the input
     * @return the shorts
     */
    private short[] getShorts(String input) {
        var bytes = getBytes(input);
        var result = new short[bytes.length];

        IntStream.range(0, bytes.length).forEach(i -> result[i] = bytes[i]);

        return result;
    }

    /**
     * Returns the given strings bytes.
     * @param input the input
     * @return the bytes
     */
    private byte[] getBytes(String input) {
        return input.getBytes(StandardCharsets.US_ASCII);
    }
}
