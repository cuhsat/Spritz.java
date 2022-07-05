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
     * Encrypts the given text with the given key.
     * @param text the plain text
     * @param key the key
     */
    public static void encrypt(short[] text, short[] key) {
        permute(text, key, v -> text[v] = (short) ((text[v] + drip()) & 0xFF));
    }

    /**
     * Decrypts the given text with the given key.
     * @param text the cipher text
     * @param key the key
     */
    public static void decrypt(short[] text, short[] key) {
        permute(text, key, v -> text[v] = (short) ((text[v] - drip()) & 0xFF));
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

    static void permute(short[] data, short[] key, IntConsumer func) {
        keySetup(key);
        IntStream.range(0, data.length).forEach(func);
    }

    static void keySetup(short[] key) {
        initializeState();
        absorb(key);
    }

    static void initializeState() {
        a = i = j = k = z = 0; w = 1;
        IntStream.range(0, N).forEach(v -> sBox[v] = (short) v);
    }

    static short drip() {
        if (a > 0) {
            shuffle();
        }
        update();
        return output();
    }

    static short output() {
        z = sBox[(j + sBox[(i + sBox[(z + k) & 0xFF]) & 0xFF]) & 0xFF];
        return z;
    }

    static void absorb(short[] b) {
        for (var v : b) {
            absorbByte(v);
        }
    }

    static void absorbByte(short b) {
        absorbNibble((short) (b & 0x0F));
        absorbNibble((short) (b >> 4));
    }

    static void absorbNibble(short x) {
        if (a == (N / 2)) {
            shuffle();
        }
        swap(a, (short) (((N / 2) + x) & 0xFF));
        a++;
    }

    static void absorbStop() {
        if (a == (N / 2)) {
            shuffle();
        }
        a++;
    }

    static void squeeze(short[] digest) {
        if (a > 0) {
            shuffle();
        }
        IntStream.range(0, min(digest.length, N)).forEach(v -> digest[v] = drip());
    }

    static void shuffle() {
        whip();
        crush();
        whip();
        crush();
        whip();
        a = 0;
    }

    static void whip() {
        IntStream.range(0, (N * 2)).forEach(v -> update());
        w += 2;
    }

    static void crush() {
        IntStream.range(0, (N / 2)).forEach(v -> {
            var t = (short) (N - 1 - v);
            if (sBox[v] > sBox[t]) {
                swap((short) v, t);
            }
        });
    }

    static void update() {
        i = (short) ((i + w) & 0xFF);
        j = (short) ((k + sBox[(j + sBox[i]) & 0xFF]) & 0xFF);
        k = (short) ((i + k + sBox[j]) & 0xFF);
        swap(i, j);
    }

    static void swap(short x, short y) {
        var t = sBox[x];
        sBox[x] = sBox[y];
        sBox[y] = t;
    }
}
