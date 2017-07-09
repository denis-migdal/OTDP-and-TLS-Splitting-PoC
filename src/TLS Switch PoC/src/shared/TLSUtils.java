package shared;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.LinkedList;
import java.util.List;


public class TLSUtils {

	final static public byte CHANGE_CIPHER_SPEC_RECORD = 0x14;
	final static public byte ALERT_RECORD = 0x15;
	final static public byte HANDSHAKE_RECORD = 0x16;
	final static public byte APP_DATA_RECORD = 0x17;
	
	final static public int TLS_HEADER_SIZE = 5;

	static public enum TLS_State { StateP, StateT, StateT2, StateP2, Close};
	
	final static private int TLS_HSIZE_FIELD = 3;
	final static private int TLS_LSIZE_FIELD = 4;
	
	final static public int readSizeFromRecordHeader(byte [] record) {
		return (record[TLS_HSIZE_FIELD] << 8) + ((int)record[TLS_LSIZE_FIELD] & 0xFF );
	}
	
	final static public void writeSizeToRecordHeader(byte [] record, int size) {
		record[TLS_HSIZE_FIELD] = (byte) (size >> 8);
		record[TLS_LSIZE_FIELD] = (byte)size;
	}
	
	
	static private List<Thread> readThreads = new LinkedList<Thread>();
	
	static public void startReadThread(final InputStream io, final ByteBuffer buffer, final CPLock lock) {
		
		Thread t = new Thread() {
			@Override
			public void run() {
				try {
					
					int nbRead;
					byte [] internal_buffer = new byte[Values.BUFFER_SIZE];
					
					while( (nbRead = io.read(internal_buffer)) != -1 && ! isInterrupted() ) {
						
						lock.waitWorkFinished();
						buffer.clear();
						buffer.put(internal_buffer, 0 , nbRead);
						buffer.flip();
						lock.giveWork();
					}
					
				} catch (IOException | InterruptedException e) {
					e.printStackTrace();
					assert false;
				}
			}
		};

		t.start();
		readThreads.add(t);
	}
	
	static public void startReadRecordThread(final InputStream io, final ByteBuffer buffer, final CPLock lock) {
		
		Thread t = new Thread() {
			@Override
			public void run() {
				try {
					
					int nbRead;
					byte [] internal_buffer = new byte[Values.BIG_BUFFER_SIZE];
					
					while( (nbRead = io.read(internal_buffer, 0, TLS_HEADER_SIZE)) != -1 && ! isInterrupted() ) {
						
						int size = readSizeFromRecordHeader(internal_buffer);
						
						int readed = 0;
						do {
							readed += io.read(internal_buffer, TLS_HEADER_SIZE + readed, size - readed);
							assert readed != -1 : "Reading error";
						} while( readed != size);
						
						lock.waitWorkFinished();
						buffer.clear();
						buffer.put(internal_buffer, 0 , nbRead + size);
						buffer.flip();
						lock.giveWork();
					}
					
				} catch (IOException | InterruptedException e) {
					e.printStackTrace();
					assert false;
				}
			}
		};

		t.start();
		readThreads.add(t);
	}
	
	
	static public void joinReadThreads() throws InterruptedException {
		
		for(Thread t : readThreads)
			t.join();
	}

	public static int readSizeFromRecordHeader(ByteBuffer buffer) {
		
		buffer.get();
		buffer.get();
		buffer.get();
		int h = buffer.get();
		int l = buffer.get();
		
		return (h << 8) + ((int)l & 0xFF);
	}

	public static void writeTLSVersionToRecordHeader(byte[] buffer,
			short protocolVersion) {
		buffer[1] = (byte) (protocolVersion >> 8);
		buffer[2] = (byte)protocolVersion;
	}
	
	public static short readTLSVersionFromRecordHeader(byte[] buffer) {
		
		int h = buffer[1];
		int l = buffer[2];
		
		return (short) ((h << 8) + ((int)l & 0xFF));
	}
	
}
