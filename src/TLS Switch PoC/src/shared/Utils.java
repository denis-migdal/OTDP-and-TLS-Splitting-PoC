package shared;

import java.nio.charset.StandardCharsets;

public class Utils {

	public static int arrayCopy( byte [] src, byte [] dst, int offset) {
		
		System.arraycopy(src, 0, dst, offset, src.length);
		
		return src.length + offset;
	}
	
	public static int arrayCopy( byte [] src, int offset, byte [] dst) {
		
		System.arraycopy(src, offset, dst, 0, dst.length);
		
		return dst.length + offset;
	}
	
	public static int stringCopy( String src, byte [] dst, int offset) {
		
		byte [] bytes_src = src.getBytes(StandardCharsets.UTF_8);
		
		dst[offset++] = (byte) bytes_src.length;
		return arrayCopy(bytes_src, dst, offset);
	}
}
