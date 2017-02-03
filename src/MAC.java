import java.nio.ByteBuffer;

import javax.xml.bind.DatatypeConverter;

public class MAC {

	public static void main(String[] args) throws Exception {
		MAC mac = new MAC();
//		String message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
//		byte[] m = message.getBytes();
//		String test = mac.getHash(m, mac.H);
//		System.out.println(test);
		
		
		byte[] m = {
				0x4e, 0x6f, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x68, 0x61, 0x73, 0x20, 0x63, 0x6f, 0x6d, 0x70, 0x6c,
				0x65, 0x74, 0x65, 0x64, 0x20, 0x6c, 0x61, 0x62, 0x20, 0x32, 0x20, 0x73, 0x6f, 0x20, 0x67, 0x69,
				0x76, 0x65, 0x20, 0x74, 0x68, 0x65, 0x6d, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x61, 0x20, 0x30
			};
		String digest = "f4b645e89faaec2ff8e443c595009c16dbdfba4b";
		byte[] d = mac.hexStringToByteArray(digest);
		int[] H = mac.shaToIntArray(d);
		
		
//		byte[] origin = mac.addPadding(m);
		byte[] origin = mac.padTheMessageWithExtra(m, 128);	//add in padding and stuff
		String original = new String(origin);
		
		String addition = "P.S. Except for Matt. Give him a 100%";
		int prevLen = origin.length * 8 + 128;
		System.out.println(prevLen);
//		for (byte b : origin) {
//			System.out.println(mac.byteToHex(b));
//		}
		String newHash = mac.getHash(addition.getBytes(), prevLen, H);
		
		System.out.println(original);
		System.out.println(mac.bytesToHex(origin));
//		System.out.println(mac.bytesToHex(theirs));
		System.out.println(addition);
		System.out.println(mac.bytesToHex(addition.getBytes()));
		byte[] sum = new byte[origin.length + addition.getBytes().length];
		System.arraycopy(origin, 0, sum, 0, origin.length);
		System.arraycopy(addition.getBytes(), 0, sum, origin.length, addition.getBytes().length);
		System.out.println(mac.bytesToHex(sum));
		String finalout = new String(sum);
		System.out.println(finalout);
		
		System.out.println(newHash);
		
		//use d as starting point to continue hashing my message
	}
	
	public byte[] addPadding(byte[] bytes) {
		byte prep = (byte) 0x80;
		int len = bytes.length + 9; //1 for prep 8 for message length as 64 bit number
		int k = len % 64;
		
		byte[] padded = new byte[len + k];
		System.arraycopy(bytes, 0, padded, 0, bytes.length);
		padded[bytes.length] = prep;
		for (int i = bytes.length + 1; i < bytes.length + 1 + k; i++) {
			padded[i] = (byte) 0x00;
		}
		
		long ml = bytes.length * 8;
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(ml);
		byte[] end = buffer.array();
		if (end.length == 8) {
			System.arraycopy(end, 0, padded, bytes.length + 1 + k, 8);
		}
		else {
			System.out.println("ERROR");
		}
		
		return padded;
	}
	
	public String getHash(byte[] data, int appendedLen, int[] H) throws Exception {
		byte[] paddedData = padTheMessageWithExtra(data, appendedLen);
		
		int passesReq = paddedData.length / 64;
		byte[] work = new byte[64];
		
		for (int passCntr = 0; passCntr < passesReq; passCntr++) {
			System.arraycopy(paddedData, 64 * passCntr, work, 0, 64);
			H = processTheBlock(work, H);
		}
		
		return intArrayToHexStr(H);
	}
	
	public String stringToHex(String x) {
		byte[] bytes = x.getBytes();
		return bytesToHex(bytes);
	}
	
	public String bytesToHex(byte[] bytes) {
		String out = "";
		for (byte b : bytes) {
			out += byteToHex(b);
		}
		
		return out;
	}
	
	public String byteToHex(byte b) {
		String out = "";
		String hex = Integer.toHexString(0xFF & b);
        if (hex.length() == 1) {
            out += '0';
        }
        out += hex;
        return out;
	}
	
	public byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	
	public int [] shaToIntArray(byte[] hash) {
		int[] result = new int[5];
		for (int i = 0; i < 20; i += 4) {
			result[i/4] = fromByteArray(hash[i], hash[i + 1], hash[i + 2], hash[i + 3]);
//			System.out.println(Integer.toHexString(result[i/4]));
		}
		
		return result;
	}
	
	private int fromByteArray(byte a, byte b, byte c, byte d) {
	     return a << 24 | (b & 0xFF) << 16 | (c & 0xFF) << 8 | (d & 0xFF);
	}
	
	//SHA-1 implementation http://www.royabubakar.com/blog/2013/10/05/sha-1-implementation-in-java/
	int j, temp;
	int A, B, C, D, E;
	int[] H = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
	int[] K = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};
	int F;
	
	private byte[] padTheMessage(byte[] data) {
		int origLength = data.length;
		int tailLength = origLength % 64;
		int padLength = 0;
		if ((64 - tailLength >= 9)) {
			padLength = 64 - tailLength;
		} else {
			padLength = 128 - tailLength;
		}
		
		byte[] thePad = new byte[padLength];
		thePad[0] = (byte) 0x80;
		long lengthInBits = origLength * 8;
		
		for (int cnt = 0; cnt < 8; cnt++) {
			thePad[thePad.length - 1 - cnt] = (byte) ((lengthInBits >> (8 * cnt)) & 0x00000000000000FF);
		}
		
		byte[] output = new byte[origLength + padLength];
		
		System.arraycopy(data, 0, output, 0, origLength);
		System.arraycopy(thePad, 0, output, origLength, thePad.length);
		
		return output;
	}
	
	private byte[] padTheMessageWithExtra(byte[] data, int len) {
		int origLength = data.length;
		int origLengthWithExtra = origLength + (len / 8);
		int tailLength = origLengthWithExtra % 64;
		int padLength = 0;
		if ((64 - tailLength >= 9)) {
			padLength = 64 - tailLength;
		} else {
			padLength = 128 - tailLength;
		}
		
		byte[] thePad = new byte[padLength];
		thePad[0] = (byte) 0x80;
		long lengthInBits = origLengthWithExtra * 8;
		
		for (int cnt = 0; cnt < 8; cnt++) {
			thePad[thePad.length - 1 - cnt] = (byte) ((lengthInBits >> (8 * cnt)) & 0x00000000000000FF);
		}
		
		byte[] output = new byte[origLength + padLength];
		
		System.arraycopy(data, 0, output, 0, origLength);
		System.arraycopy(thePad, 0, output, origLength, thePad.length);
		
		return output;
	}
	
	private int[] processTheBlock(byte[] work, int H[]) {
//		System.out.println("H0:" + Integer.toHexString(H[0]));
//		System.out.println("H1:" + Integer.toHexString(H[1]));
//		System.out.println("H2:" + Integer.toHexString(H[2]));
//		System.out.println("H3:" + Integer.toHexString(H[3]));
//		System.out.println("H4:" + Integer.toHexString(H[4]));
		
		int[] W = new int[80];
		for (int outer = 0; outer < 16; outer++) {
			int temp = 0;
				for (int inner = 0; inner < 4; inner++) {
					temp = (work[outer * 4 + inner] & 0x000000FF) << (24 - inner * 8);
					W[outer] = W[outer] | temp;
				}
		}
		
		for (int j = 16; j < 80; j++) {
			W[j] = rotateLeft(W[j - 3] ^ W[j - 8] ^ W[j - 14] ^ W[j - 16], 1);
		}
		
		A = H[0];
		B = H[1];
		C = H[2];
		D = H[3];
		E = H[4];
		
		for (int j = 0; j < 20; j++) {
			F = (B & C) | ((~B) & D);
			//	K = 0x5A827999;
			temp = rotateLeft(A, 5) + F + E + K[0] + W[j];
//			System.out.println(Integer.toHexString(K[0]));
			E = D;
			D = C;
			C = rotateLeft(B, 30);
			B = A;
			A = temp;
		}
		
		for (int j = 20; j < 40; j++) {
			F = B ^ C ^ D;
			//   K = 0x6ED9EBA1;
			temp = rotateLeft(A, 5) + F + E + K[1] + W[j];
//			System.out.println(Integer.toHexString(K[1]));
			E = D;
			D = C;
			C = rotateLeft(B, 30);
			B = A;
			A = temp;
		}
		
		for (int j = 40; j < 60; j++) {
			F = (B & C) | (B & D) | (C & D);
			//   K = 0x8F1BBCDC;
			temp = rotateLeft(A, 5) + F + E + K[2] + W[j];
			E = D;
			D = C;
			C = rotateLeft(B, 30);
			B = A;
			A = temp;
		}
		
		for (int j = 60; j < 80; j++) {
			F = B ^ C ^ D;
			//   K = 0xCA62C1D6;
			temp = rotateLeft(A, 5) + F + E + K[3] + W[j];
			E = D;
			D = C;
			C = rotateLeft(B, 30);
			B = A;
			A = temp;
		}

		H[0] += A;
		H[1] += B;
		H[2] += C;
		H[3] += D;
		H[4] += E;
		
//		int n;
//		for (n = 0; n < 16; n++) {
//			System.out.println("W[" + n + "] = " + toHexString(W[n]));
//		}
//		
//		System.out.println("H0:" + Integer.toHexString(H[0]));
//		System.out.println("H1:" + Integer.toHexString(H[1]));
//		System.out.println("H2:" + Integer.toHexString(H[2]));
//		System.out.println("H3:" + Integer.toHexString(H[3]));
//		System.out.println("H4:" + Integer.toHexString(H[4]));
		
		return H;
	}
	
	final int rotateLeft(int value, int bits) {
		int q = (value << bits) | (value >>> (32 - bits));
		return q;
	}
	
	public String toHexString(final ByteBuffer bb) {
		final StringBuffer sb = new StringBuffer();
		for (int i = 0; i < bb.limit(); i += 4) {
			if (i % 4 == 0) {
				sb.append('\n');
			}
			sb.append(toHexString(bb.getInt(i))).append(' ');
		}
		sb.append('\n');
		return sb.toString();
	}
	
	static final String toHexString(int x) {
		return padStr(Integer.toHexString(x));
	}
	
	static final String ZEROS = "00000000";

	static final String padStr(String s) {
		if (s.length() > 8) {
			return s.substring(s.length() - 8);
		}
		return ZEROS.substring(s.length()) + s;
	}

	private String intArrayToHexStr(int[] data) {
		String output = "";
		String tempStr = "";
		int tempInt = 0;
		for (int cnt = 0; cnt < data.length; cnt++) {
		
			tempInt = data[cnt];
			
			tempStr = Integer.toHexString(tempInt);
			
			if (tempStr.length() == 1) {
				tempStr = "0000000" + tempStr;
			} else if (tempStr.length() == 2) {
				tempStr = "000000" + tempStr;
			} else if (tempStr.length() == 3) {
				tempStr = "00000" + tempStr;
			} else if (tempStr.length() == 4) {
				tempStr = "0000" + tempStr;
			} else if (tempStr.length() == 5) {
				tempStr = "000" + tempStr;
			} else if (tempStr.length() == 6) {
				tempStr = "00" + tempStr;
			} else if (tempStr.length() == 7) {
				tempStr = "0" + tempStr;
			}
			output = output + tempStr;
		}//end for loop
		return output;
	}//
}

