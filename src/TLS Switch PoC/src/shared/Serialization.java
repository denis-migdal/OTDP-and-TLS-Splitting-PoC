package shared;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.lang.reflect.Field;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public class Serialization {

	static public Serialized serialize(Object o) throws IllegalArgumentException, IllegalAccessException, InstantiationException, NoSuchMethodException, SecurityException, InvocationTargetException {

		Map<Object, Object> instanciedObjects = new HashMap<Object, Object>();
		
		return serialize(o, instanciedObjects);
	}
	

	static public Serialized serialize(Object o, Map<Object, Object> instanciedObjects) throws IllegalArgumentException, IllegalAccessException, InstantiationException {
		
		Class<?> c = o.getClass();
		ArrayList<Field> fields = Introspection.getAllFields(c);

		Serialized serial = new Serialized();
		serial.type = c.getName();
		
		instanciedObjects.put(o, serial);
		
		for( Field f : fields ) {

			if( java.lang.reflect.Modifier.isStatic(f.getModifiers() ) )
				continue;
			
			f.setAccessible(true);
			
			Object value = f.get(o);
			
			
			// optimisation 1
			if(value == null)
				continue;
			
			// optimisation 2
			if( value.getClass().getName().compareTo("com.sun.crypto.provider.SunJCE") == 0) {
				Serialized s = new Serialized();
				s.type = "com.sun.crypto.provider.SunJCE";
				
				serial.fields.add( new Serialized.Field(f.getName(), s) );
				
				f.setAccessible(false);
				
				continue;
			}
			
			if( ! isDirectlySerialisable(f, o)
					&& value.getClass().getName().compareTo("sun.security.util.Debug") != 0) {
				
				if( instanciedObjects.containsKey(value) ) {
					value = instanciedObjects.get(value);
				}
				else if( value.getClass().getName().compareTo("java.lang.Object") == 0 )
					value = new O();
				else {
					value = serialize(value, instanciedObjects);
				}
			}
			
			serial.fields.add( new Serialized.Field(f.getName(), (Serializable)value) );
			
			f.setAccessible(false);
		}
		
		return serial;
	}
	
	
	
	static public class Serialized implements Serializable {
		private static final long serialVersionUID = 1L;
		
		public String type;
		
		public static class Field implements Serializable {
			private static final long serialVersionUID = 1L;
			public Field(String name, Serializable value) {
				this.name = name;
				this.value = value;
			}
			String name;
			Serializable value;
		}
		
		public ArrayList<Field> fields = new ArrayList<Field>();
		
		private void writeObject(ObjectOutputStream oos) throws IOException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
	
			byte [] buf = type.getBytes(StandardCharsets.UTF_8);
			oos.write( buf.length);
			oos.write( buf );
			
			oos.write( fields.size());
			
			for( Field f : fields) {
				
				buf = f.name.getBytes(StandardCharsets.UTF_8);
				oos.write( buf.length);
				oos.write( buf );
				
				oos.writeObject(f.value);
			}
		}
		
		private void readObject(ObjectInputStream ois)
				throws ClassNotFoundException, IOException {
			
			int size = ois.read();
			byte [] buf = new byte[size];
			ois.read(buf);
			type = new String(buf, StandardCharsets.UTF_8);
			
			int nbElement = ois.read();
			fields = new ArrayList<Field>();
			
			for( int i = 0 ; i < nbElement ; ++i) {
				
				
				size = ois.read();
				buf = new byte[size];
				ois.read(buf);
				String name = new String(buf, StandardCharsets.UTF_8);
				
				Serializable value = (Serializable) ois.readObject();
				
				fields.add( new Field(name, value));
			}
		}
	}
	
	static public class O implements Serializable {

		private static final long serialVersionUID = 1L;
		
	}
	
	
	public static boolean isDirectlySerialisable(Field f, Object obj) throws IllegalArgumentException, IllegalAccessException {
		
		boolean access = f.isAccessible();
		
		f.setAccessible(true);
		Object o = f.get(obj);
		f.setAccessible(access);
		return o == null || f.getType().isPrimitive() || o instanceof Serializable;
	}
	
	public static byte[] toBytes( Serializable o ) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream( baos );
		oos.writeObject( o );
		oos.close();
		return baos.toByteArray();
	}
	

	public static Object fromBytes( byte[] b, int i, int len ) throws IOException, ClassNotFoundException {
		ByteArrayInputStream bais = new ByteArrayInputStream(b, i, len);
		ObjectInputStream ois = new ObjectInputStream( bais );
		Object o = ois.readObject();
		ois.close();
		return o;
	}
	

	public static Object unserialize(Serialized s) throws IllegalArgumentException, IllegalAccessException, InstantiationException, NoSuchMethodException, SecurityException, InvocationTargetException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, NoSuchFieldException {

		Map<Object, Object> instanciedObjects = new HashMap<Object, Object>();
		
		return unserialize(s, instanciedObjects);
	}
	
	@SuppressWarnings("restriction")
	public static Object unserialize(Serialized serial, Map<Object, Object> instanciedObjects) throws IllegalArgumentException, IllegalAccessException, InstantiationException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, NoSuchFieldException, SecurityException, NoSuchMethodException, InvocationTargetException {
		
		Class<?> c = Class.forName( serial.type );
		Object o = Introspection.allocate(c);
		
		instanciedObjects.put(serial, o);
		
		for( Serialized.Field field : serial.fields ) {
			
			Field f = Introspection.getField(c, field.name);
			f.setAccessible(true);
			
			Object value = field.value;
			
			if( value instanceof Serialized ) {
				if( instanciedObjects.containsKey(value) ) {
					value = instanciedObjects.get(value);
				} else if( ((Serialized)value).type.compareTo("com.sun.crypto.provider.SunJCE") == 0) {
					value = new com.sun.crypto.provider.SunJCE();
				} else {
					value = unserialize( (Serialized)value);
				}
			}
			
			f.set(o, value);
			
			f.setAccessible(false);
		}
		
		return o;
	}
	

}
