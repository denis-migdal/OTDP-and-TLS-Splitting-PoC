package proxy;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import shared.Introspection;
import shared.TLSSessionInfo;
import shared.TLSUtils;
import shared.Values;
import shared.Introspection.SSLSessionInfo;
import shared.Serialization;
import shared.Serialization.Serialized;

public class SSLProxyEngine {

	private SSLEngine engine = null;
	private ByteBuffer clearInput = null;
	private ByteBuffer cipherOutput = null;
	
	private byte [] readBuffer = new byte[Values.BUFFER_SIZE];
	private byte [] writeBuffer = new byte[Values.BUFFER_SIZE];
	
	public void goStateP(byte[] buffer, int i, int len) throws ClassNotFoundException, IOException, IllegalArgumentException, IllegalAccessException, InstantiationException, NoSuchMethodException, SecurityException, InvocationTargetException, IllegalBlockSizeException, BadPaddingException, NoSuchFieldException {
		
		Serialized serial = (Serialized) Serialization.fromBytes(buffer, i, len);
		
		SSLSessionInfo pse = (SSLSessionInfo)Serialization.unserialize(serial);
		engine = Introspection.createSEFromSSLSI(pse);
		
		SSLSession session = engine.getSession();
		int appCapacity = session.getApplicationBufferSize();
		int netCapacity = session.getPacketBufferSize();

		cipherOutput = ByteBuffer.allocateDirect(netCapacity);
		
		clearInput = ByteBuffer.allocate(appCapacity + 50);
	}

	public byte[] goStateT() throws IllegalArgumentException, IllegalAccessException, InstantiationException, NoSuchMethodException, SecurityException, InvocationTargetException, IOException, NoSuchFieldException {
		
		Introspection.SSLSessionInfo pse = Introspection.extractSSLSIfromSE( engine );
		engine = null;
		
		Serialized serial = Serialization.serialize(pse);
		return Serialization.toBytes(serial);
	}

	public void receive(PrintStream out, ByteBuffer cipherInput) throws SSLException {

		clearInput.clear();
		
		do {
			engine.unwrap(cipherInput, clearInput);
		} while( cipherInput.hasRemaining() );
		
		clearInput.flip();
		int size = clearInput.remaining();
		clearInput.get(readBuffer, 0, size);
		System.out.print( new String(readBuffer, 0, size, StandardCharsets.UTF_8) );
	}

	public void send(OutputStream oo, ByteBuffer clearOutput) throws IOException {
		
		cipherOutput.clear();
		
		engine.wrap(clearOutput, cipherOutput);
		
		cipherOutput.flip();
		
		int size = cipherOutput.remaining();
		cipherOutput.get(writeBuffer, 0, size );
		
		oo.write(writeBuffer, 0, size);
	}

	public byte[] extractSequenceNumbers() throws ClassNotFoundException, NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
		
		Object readMAC = Introspection.extract(engine, "readMAC");
		Object writeMAC = Introspection.extract(engine, "writeMAC");
		
		byte [] readBlock = (byte[])Introspection.extract(readMAC, "block");
		byte [] writeBlock = (byte[])Introspection.extract(writeMAC, "block");
		
		int len = 8;
		int offset = 0;
		
		while( readBlock[offset] == 0 && writeBlock[offset] == 0)
			offset++;
		len -= offset;
		
		byte [] seq_num = new byte[2*len];
		
		System.arraycopy(readBlock, offset, seq_num, 0, len);
		System.arraycopy(writeBlock, offset, seq_num, len, len);
		
		return seq_num;
	}

	public void goStateP2(byte[] buffer, int offset, int len) throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException, InvocationTargetException, ClassNotFoundException, NoSuchMethodException, InstantiationException, NoSuchAlgorithmException {
		
		short protocolVersion = TLSUtils.readTLSVersionFromRecordHeader(buffer);
		
		offset += TLSUtils.TLS_HEADER_SIZE;
		len -= TLSUtils.TLS_HEADER_SIZE;
		
		TLSSessionInfo sessionInfo = TLSSessionInfo.fromBytes(protocolVersion,
															  buffer, offset, len);
		
		engine = (SSLEngine) Introspection.createDummySE();
		sessionInfo.updateEngineCiphers(engine);
		

		SSLSession session = engine.getSession();
		int appCapacity = session.getApplicationBufferSize();
		int netCapacity = session.getPacketBufferSize();

		cipherOutput = ByteBuffer.allocateDirect(netCapacity);
		
		clearInput = ByteBuffer.allocate(appCapacity + 50);
	}
}