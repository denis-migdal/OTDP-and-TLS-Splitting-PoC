package shared;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;


public class TLSSessionInfo {

	private byte protocolVersion_major = 0; // In TLS Header
	private byte protocolVersion_minor; // In TLS Header
	
	private byte cipherSuiteID_high = 0; // REQUIRED
	private byte cipherSuiteID_low = 0; // REQUIRED

	private byte [][] macSecretKeys; // REQUIRED
	private byte [][] cipherSecretKeys; // REQUIRED
	
	public byte [][] seq_nums = new byte[][]{{0,0,0,0,0,0,0,1},{0,0,0,0,0,0,0,1}}; // value after an handshake
	
	public byte [] toBytes() {

		int len = length();
		byte [] buffer = new byte[len];
		int offset = 0;
		
		return toBytes(buffer, offset, len);
	}
	
	public byte [] toBytes(byte [] buffer, int offset, int len) {
		
		//TODO delete useless 0 in seq_num.
		
		// In TLS header
		//buffer[offset++] = protocolVersion_major;
		//buffer[offset++] = protocolVersion_minor;
		
		buffer[offset++] = cipherSuiteID_high;
		buffer[offset++] = cipherSuiteID_low;
		
		offset = Utils.arrayCopy(macSecretKeys[READ], buffer, offset);
		offset = Utils.arrayCopy(macSecretKeys[WRITE], buffer, offset);
		
		offset = Utils.arrayCopy(cipherSecretKeys[READ], buffer, offset);
		offset = Utils.arrayCopy(cipherSecretKeys[WRITE], buffer, offset);
		
		//Always = 00000001 00000001 after an handshake.
		//offset = Utils.arrayCopy(seq_nums[READ], buffer, offset);
		//offset = Utils.arrayCopy(seq_nums[WRITE], buffer, offset);

		
		return buffer;
	}
	
	public void extractFromBytes(byte [] buffer) throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException, InvocationTargetException, ClassNotFoundException {
	
		extractFromBytes(buffer, 0, buffer.length);
	}
	
	public void extractFromBytes(byte [] buffer, int offset, int len) throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException, InvocationTargetException, ClassNotFoundException {

		//In TLS Header
		//protocolVersion_major = buffer[offset++];
		//protocolVersion_minor = buffer[offset++];
		
		cipherSuiteID_high = buffer[offset++];
		cipherSuiteID_low = buffer[offset++];
		
		int macSize = (int)Introspection.extract(generateSunMacAlg(), "size");
		int cipherKeySize = (int)Introspection.extract(generateBulkCipher(), "keySize");
		
		macSecretKeys = new byte[2][macSize];
		cipherSecretKeys = new byte[2][cipherKeySize];
		
		offset = Utils.arrayCopy(buffer, offset, macSecretKeys[READ]);
		offset = Utils.arrayCopy(buffer, offset, macSecretKeys[WRITE]);
		
		offset = Utils.arrayCopy(buffer, offset, cipherSecretKeys[READ]);
		offset = Utils.arrayCopy(buffer, offset, cipherSecretKeys[WRITE]);
		
		//Always = 00000001 00000001 after an handshake.
		//offset = Utils.arrayCopy(buffer, offset, seq_nums[READ]);
		//offset = Utils.arrayCopy(buffer, offset, seq_nums[WRITE]);
	}
	
	static public TLSSessionInfo fromBytes(short protocolVersion, byte [] buffer, int offset, int len) throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException, InvocationTargetException, ClassNotFoundException {
		
		TLSSessionInfo tsi = new TLSSessionInfo();

		tsi.setProtocolVersion(protocolVersion);
		tsi.extractFromBytes(buffer, offset, len);
		
		return tsi;
	}
	
	static public TLSSessionInfo fromBytes(short protocolVersion, byte [] buffer) throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException, InvocationTargetException, ClassNotFoundException {
		
		return fromBytes(protocolVersion, buffer, 0, buffer.length);
	}
	
	public void extractReadMAC(Object handshaker) throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException, InvocationTargetException, ClassNotFoundException {
		extractMAC(handshaker, READ);
	}

	public void extractWriteMAC(Object handshaker) throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException, InvocationTargetException, ClassNotFoundException {
		extractMAC(handshaker, WRITE);
	}
	
	private final static int WRITE = 1;
	private final static int READ = 0;
	
	private static final String[] macSecretFields = {"svrMacSecret", "clntMacSecret"};
	
	private void extractMAC(Object handshaker, int dir) throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException, InvocationTargetException, ClassNotFoundException {
		
		extractSunProtocolVersion(handshaker);
		extractSunCipherSuite(handshaker);
		extractMacSecretKeySpec(handshaker, dir);
	}
	
	public void extractReadCipher(Object handshaker) throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
		extractCipher(handshaker, READ);
	}

	public void extractWriteCipher(Object handshaker) throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
		extractCipher(handshaker, WRITE);
	}
	

	private static final String[] cipherSecretFields = {"svrWriteKey", "clntWriteKey"};
	
	private void extractCipher(Object handshaker, int dir) throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
	
		extractSunProtocolVersion(handshaker);
		extractSunCipherSuite(handshaker);
		extractCipherSecretKeySpec(handshaker, dir);
	}
	
	public void updateEngineCiphers(Object engine) throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, NoSuchFieldException, SecurityException, ClassNotFoundException, NoSuchMethodException, NoSuchAlgorithmException {
		
		updateEngineReadCiphers(engine);
		updateEngineWriteCiphers(engine);
	}
	
	public void updateEngineReadCiphers(Object engine) throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, NoSuchFieldException, SecurityException, ClassNotFoundException, NoSuchMethodException, NoSuchAlgorithmException {
		updateEngineCiphers(engine, READ);
	}

	public void updateEngineWriteCiphers(Object engine) throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, NoSuchFieldException, SecurityException, ClassNotFoundException, NoSuchMethodException, NoSuchAlgorithmException {
		updateEngineCiphers(engine, WRITE);
		
	}
	
	private final static String [] macFieldNames = new String []{"readMAC", "writeMAC"};
	private final static String [] cipherFieldNames = new String []{"readCipher", "writeCipher"};
	
	private void updateEngineCiphers(Object engine, int dir) throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, NoSuchFieldException, SecurityException, ClassNotFoundException, NoSuchMethodException, NoSuchAlgorithmException {

		Class<?> c_MAC = Class.forName("sun.security.ssl.MAC");
		Class<?> c_CipherBox = Class.forName("sun.security.ssl.CipherBox");
		Class<?> c_MACAlg = Class.forName("sun.security.ssl.CipherSuite$MacAlg");
		Class<?> c_ProtocolVersion = Class.forName("sun.security.ssl.ProtocolVersion");
		Class<?> c_SecretKey = Class.forName("javax.crypto.SecretKey");
		Class<?> c_IvParameterSpec = Class.forName("javax.crypto.spec.IvParameterSpec");
		Class<?> c_SecureRandom = Class.forName("java.security.SecureRandom");
		Class<?> c_BulkCipher = Class.forName("sun.security.ssl.CipherSuite$BulkCipher");
		
		{
			
			Constructor<?> ctr = c_MAC.getDeclaredConstructor(c_MACAlg, c_ProtocolVersion, c_SecretKey);
			
			ctr.setAccessible(true);
			Object mac = ctr.newInstance(generateSunMacAlg(),
										 generateSunProtocolVersion(),
										 generateMacSecretKeySpec(dir) );
			ctr.setAccessible(false);
			

			byte [] block = (byte[])Introspection.extract(mac, "block");
			Utils.arrayCopy(seq_nums[dir], block, 0);
			
			Introspection.set(engine, macFieldNames[dir], mac);
		}

		{
			
			Constructor<?> ctr = c_CipherBox.getDeclaredConstructor(c_ProtocolVersion, c_BulkCipher, c_SecretKey, c_IvParameterSpec, c_SecureRandom, boolean.class);
			
			ctr.setAccessible(true);
			
			SecureRandom random = SecureRandom.getInstance("NativePRNG");
			
			Object cipher = ctr.newInstance( generateSunProtocolVersion(),
											 generateBulkCipher(),
											 generateCipherSecretKeySpec(dir),
											 null, random, dir == WRITE);
			ctr.setAccessible(false);
			
			
			Introspection.set(engine, cipherFieldNames[dir], cipher);
		}
	}
	
	private Object generateSunProtocolVersion() throws IllegalAccessException, IllegalArgumentException, InvocationTargetException, ClassNotFoundException {
		
		Class<?> c = Class.forName("sun.security.ssl.ProtocolVersion");
		Method m = Introspection.getMethod(c, "valueOf", int.class, int.class);
		return Introspection.invoke(null, m, protocolVersion_major, protocolVersion_minor);
	}
	
	private void extractSunProtocolVersion(Object handshaker) throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {

		if( protocolVersion_major != 0)
			return;
		
		Object pv = Introspection.extract(handshaker, "protocolVersion");
		
		protocolVersion_major = (byte) Introspection.extract(pv, "major");
		protocolVersion_minor = (byte) Introspection.extract(pv, "minor");
	}

	public void extractSeqNums(Object engine) throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
		
		for(int dir = 0; dir < 2; ++dir) {
			
			Object mac = Introspection.extract(engine, macFieldNames[dir]);
			byte [] block = (byte[])Introspection.extract(mac, "block");
			Utils.arrayCopy(block, 0, seq_nums[dir]);
			
		}
	}
	
	private void extractCipherSecretKeySpec(Object handshaker, int dir) throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
		
		SecretKeySpec secret = (SecretKeySpec)Introspection.extract(handshaker, cipherSecretFields[dir]);
		
		cipherSecretKeys[dir] = secret.getEncoded();
	}
	
	private SecretKeySpec generateCipherSecretKeySpec(int dir) throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException, ClassNotFoundException, InvocationTargetException {
		
		return new SecretKeySpec(cipherSecretKeys[dir], getCipherAlgorithmName() );
	}
	

	private void extractMacSecretKeySpec(Object handshaker, int dir) throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
		
		SecretKeySpec secret = (SecretKeySpec)Introspection.extract(handshaker, macSecretFields[dir]);
		
		macSecretKeys[dir] = secret.getEncoded();
	}
	
	private SecretKeySpec generateMacSecretKeySpec(int dir) {
		
		return new SecretKeySpec(macSecretKeys[dir], "Mac" );
	}
	

	private void extractSunCipherSuite(Object handshaker) throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
		
		if( cipherSuiteID_low != 0 && cipherSuiteID_high != 0)
			return;
		
		Object cipherSuite = Introspection.extract(handshaker, "cipherSuite");
		int cipherSuiteID = (int)Introspection.extract(cipherSuite, "id");
		cipherSuiteID_high = (byte)(cipherSuiteID >> 8);
		cipherSuiteID_low = (byte)cipherSuiteID;
		
		Object macAlg = Introspection.extract(cipherSuite, "macAlg");
		macSecretKeys = new byte[2][ (int)Introspection.extract(macAlg, "size") ];
		
		Object bulkCipher = Introspection.extract(cipherSuite, "cipher");
		cipherSecretKeys = new byte[2][ (int) Introspection.extract(bulkCipher, "keySize") ];
	}
	
	private Object generateSunCipherSuite() throws ClassNotFoundException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
		
		Class<?> c_cipherSuite = Class.forName("sun.security.ssl.CipherSuite");
		
		Method m = Introspection.getMethod(c_cipherSuite, "valueOf", int.class, int.class);
		Object cipherSuite = Introspection.invoke(null, m, cipherSuiteID_high, cipherSuiteID_low);
		
		return cipherSuite;
	}
	
	private Object generateSunMacAlg() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException, ClassNotFoundException, InvocationTargetException {
		
		Object cipherSuite = generateSunCipherSuite();
		return Introspection.extract(cipherSuite, "macAlg");
	}
	
	private Object generateBulkCipher() throws ClassNotFoundException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, NoSuchFieldException, SecurityException {

		Object cipherSuite = generateSunCipherSuite();
		return Introspection.extract(cipherSuite, "cipher");
	}
	
	private String getCipherAlgorithmName() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException, ClassNotFoundException, InvocationTargetException {

		Object cipherSuite = generateSunCipherSuite();
		Object cipher = Introspection.extract(cipherSuite, "cipher");
		return (String) Introspection.extract(cipher, "algorithm");
	}

	public int length() {
		return 2*1 + 2*macSecretKeys[0].length + 2*cipherSecretKeys[0].length;
	}

	public short protocolVersion() {
		return (short) ((protocolVersion_major << 8) + (0xFF & protocolVersion_minor) );
	}
	
	public void setProtocolVersion(short protocolVersion) {
		protocolVersion_major = (byte) (protocolVersion >> 8);
		protocolVersion_minor = (byte)protocolVersion;
	}
}
