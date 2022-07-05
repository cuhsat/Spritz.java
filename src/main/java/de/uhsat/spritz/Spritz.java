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

import java.util.function.*;
import java.util.stream.*;

import static java.lang.Integer.min;

/**
 * Implementation of the Spritz cipher.
 */
public final class Spritz {
    private final static short N = 256;
    private final static short[] sBox = new short[N];
    private static short a, i, j, k, w, z;

    /**
     * Encrypts the given data with the given key.
     * @param data the data
     * @param key the key
     */
    public static void encrypt(short[] data, short[] key) {
        permute(data, key, v -> data[v] = (short) ((data[v] + drip()) & 0xFF));
    }

    /**
     * Encrypts the given data with the given key and initialization vector.
     * @param data the data
     * @param key the key
     * @param iv the initialization vector
     */
    public static void encrypt(short[] data, short[] key, short[] iv) {
        permute(data, key, iv, v -> data[v] = (short) ((data[v] + drip()) & 0xFF));
    }

    /**
     * Decrypts the given data with the given key.
     * @param data the data
     * @param key the key
     */
    public static void decrypt(short[] data, short[] key) {
        permute(data, key, v -> data[v] = (short) ((data[v] - drip()) & 0xFF));
    }

    /**
     * Decrypts the given data with the given key and initialization vector.
     * @param data the data
     * @param key the key
     * @param iv the initialization vector
     */
    public static void decrypt(short[] data, short[] key, short[] iv) {
        permute(data, key, iv, v -> data[v] = (short) ((data[v] - drip()) & 0xFF));
    }

    /**
     * Creates the message authentication code.
     * @param message the message
     * @param key the key
     * @param code the authentication code
     */
    public static void mac(short[] message, short[] key, short[] code) {
        initializeState();
        absorb(key);
        absorbStop();
        absorb(message);
        absorbStop();
        absorb(new short[] { (short) code.length });
        squeeze(code);
    }

    /**
     * Hashes the given message and fills in the digest.
     * @param message the message
     * @param digest the message digest
     */
    public static void hash(short[] message, short[] digest) {
        initializeState();
        absorb(message);
        absorbStop();
        absorb(new short[] { (short) digest.length });
        squeeze(digest);
    }

    /**
     * Generates the basic output for the given input.
     * @param input the input
     * @param output the output
     */
    static void basic(short[] input, short[] output) {
        initializeState();
        absorb(input);
        squeeze(output);
    }

    /**
     * Permutes the given data and key with a lambda.
     * @param data the data
     * @param key the key
     * @param action the lambda
     */
    static void permute(short[] data, short[] key, IntConsumer action) {
        keySetup(key);
        IntStream.range(0, data.length).forEach(action);
    }

    /**
     * Permutes the given data, key and initialization vector with a lambda.
     * @param data the data
     * @param key the key
     * @param iv the initialization vector
     * @param action the lambda
     */
    static void permute(short[] data, short[] key, short[] iv, IntConsumer action) {
        keySetup(key);
        absorbStop();
        absorb(iv);
        IntStream.range(0, data.length).forEach(action);
    }

    /**
     * Sets up the cipher with the given key.
     * @param key the key
     */
    static void keySetup(short[] key) {
        initializeState();
        absorb(key);
    }

    /**
     * Initializes the ciphers internal states and the S-box.
     */
    static void initializeState() {
        a = i = j = k = z = 0; w = 1;
        IntStream.range(0, N).forEach(v -> sBox[v] = (short) v);
    }

    /**
     * Produces multiple output values.
     * @param values the output values
     */
    static void squeeze(short[] values) {
        if (a > 0) {
            shuffle();
        }
        IntStream.range(0, min(values.length, N)).forEach(v -> values[v] = drip());
    }

    /**
     * Produces a single output value.
     * @return the output value
     */
    static short drip() {
        if (a > 0) {
            shuffle();
        }
        update();
        return output();
    }

    /**
     * Returns a single output value.
     * @return the output value
     */
    static short output() {
        z = sBox[(j + sBox[(i + sBox[(z + k) & 0xFF]) & 0xFF]) & 0xFF];
        return z;
    }

    /**
     * Absorbs multiple bytes.
     * @param values the bytes
     */
    static void absorb(short[] values) {
        for (var value : values) {
            absorbByte(value);
        }
    }

    /**
     * Absorbs a byte.
     * @param value the byte
     */
    static void absorbByte(short value) {
        absorbNibble((short) (value & 0x0F));
        absorbNibble((short) (value >> 4));
    }

    /**
     * Absorbs a nibble.
     * @param value the nibble
     */
    static void absorbNibble(short value) {
        if (a == (N / 2)) {
            shuffle();
        }
        swap(a, (short) (((N / 2) + value) & 0xFF));
        a++;
    }

    /**
     * Absorbs the special stop symbol.
     */
    static void absorbStop() {
        if (a == (N / 2)) {
            shuffle();
        }
        a++;
    }

    /**
     * Calculates the ciphers internal states.
     */
    static void shuffle() {
        whip();
        crush();
        whip();
        crush();
        whip();
        a = 0;
    }

    /**
     * Calculates the ciphers internal states.
     */
    static void whip() {
        IntStream.range(0, (N * 2)).forEach(v -> update());
        w += 2;
    }

    /**
     * Calculates the ciphers internal states.
     */
    static void crush() {
        IntStream.range(0, (N / 2)).forEach(v -> {
            var t = (short) (N - 1 - v);
            if (sBox[v] > sBox[t]) {
                swap((short) v, t);
            }
        });
    }

    /**
     * Updates the S-box.
     */
    static void update() {
        i = (short) ((i + w) & 0xFF);
        j = (short) ((k + sBox[(j + sBox[i]) & 0xFF]) & 0xFF);
        k = (short) ((i + k + sBox[j]) & 0xFF);
        swap(i, j);
    }

    /**
     * Swaps two values in the S-box.
     * @param x the first index
     * @param y the second index
     */
    static void swap(short x, short y) {
        var t = sBox[x];
        sBox[x] = sBox[y];
        sBox[y] = t;
    }
}
