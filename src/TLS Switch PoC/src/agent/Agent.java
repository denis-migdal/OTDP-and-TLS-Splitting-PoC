package agent;

import java.lang.instrument.Instrumentation;

public class Agent {
	public static void premain(String agentArgs, Instrumentation inst) {
        
        // registers the transformer
        inst.addTransformer(new HandshakerTransformer());
    }
}
