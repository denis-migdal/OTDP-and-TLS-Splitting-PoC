package shared;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;

public class Copy {

	public static Object copy(Object a, Map<Object, Object> instanciedObjects) throws NoSuchMethodException, SecurityException, InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {

		Class<?> c = a.getClass();
		
		Object b = Introspection.allocate( c );
		instanciedObjects.put(a, b);
		
		for( Field f : Introspection.getAllFields(c) ) {
			
			if( java.lang.reflect.Modifier.isStatic(f.getModifiers() ) )
				continue;
			
			f.setAccessible(true);
			Object field = f.get(a);
			
			if( ! Serialization.isDirectlySerialisable(f, a)
					&& field.getClass().getName().compareTo("sun.security.util.Debug") != 0
					&& field.getClass().getName().compareTo("java.lang.Object") != 0 ) {
				
				if( instanciedObjects.containsKey(field) )
					field = instanciedObjects.get(field);
				else
					field = copy(field, instanciedObjects);
			}
			
			f.set(b, field);
			
			f.setAccessible(false);
		}
		
		return b;
	}
	
	public static Object copy(Object a) throws IllegalArgumentException, IllegalAccessException, InstantiationException, NoSuchMethodException, SecurityException, InvocationTargetException {

		Map<Object, Object> instanciedObjects = new HashMap<Object, Object>();
		
		return copy(a, instanciedObjects);
	}
}
