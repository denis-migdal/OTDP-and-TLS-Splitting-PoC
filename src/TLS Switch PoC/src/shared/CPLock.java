package shared;

import java.util.concurrent.Semaphore;

public class CPLock {
	
	public enum State {NEED_CREATE_WORK, CREATING_WORK, NEED_DO_WORK, DOING_WORK};

	private State currentState = State.NEED_CREATE_WORK;
	
	private Semaphore c = new Semaphore(0);
	private Semaphore p = new Semaphore(1);
	
	public CPLock() {
	}
	
	public void waitWork() throws InterruptedException {
		c.acquire();
		currentState = State.DOING_WORK;
	}
	
	public void giveWork() {
		c.release();
		currentState = State.NEED_DO_WORK;
	}
	
	public void workFinished() {
		p.release();
		currentState = State.NEED_CREATE_WORK;
	}
	
	public void waitWorkFinished() throws InterruptedException {
		p.acquire();
		currentState = State.CREATING_WORK;
	}
	
	public State state() {
		return currentState;
	}

}