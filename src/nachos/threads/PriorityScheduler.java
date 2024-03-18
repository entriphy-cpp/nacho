package nachos.threads;

import nachos.machine.*;

import java.util.*;

/**
 * A scheduler that chooses threads based on their priorities.
 *
 * <p>
 * A priority scheduler associates a priority with each thread. The next thread
 * to be dequeued is always a thread with priority no less than any other
 * waiting thread's priority. Like a round-robin scheduler, the thread that is
 * dequeued is, among all the threads of the same (highest) priority, the
 * thread that has been waiting longest.
 *
 * <p>
 * Essentially, a priority scheduler gives access in a round-robin fashion to
 * all the highest-priority threads, and ignores all other threads. This has
 * the potential to
 * starve a thread if there's always a thread waiting with higher priority.
 *
 * <p>
 * A priority scheduler must partially solve the priority inversion problem; in
 * particular, priority must be donated through locks, and through joins.
 */
public class PriorityScheduler extends Scheduler {
	// JDK 8 anti-feature, can't put this inside PriorityQueue
	// Unique id for an instance of PriorityQueue:
	private static long id = 1;
	/**
	 * The default priority for a new thread. Do not change this value.
	 */
	public static final int priorityDefault = 1;
	/**
	 * The minimum priority that a thread can have. Do not change this value.
	 */
	public static final int priorityMinimum = 0;
	/**
	 * The maximum priority that a thread can have. Do not change this value.
	 */
	public static final int priorityMaximum = 7;


	private class PriorityComparator implements Comparator<KThread> {

		@Override
		public int compare(KThread o1, KThread o2) {
			ThreadState s1 = (ThreadState) o1.schedulingState;
			ThreadState s2 = (ThreadState) o2.schedulingState;
			// highest and oldest priority goes to the top
			if (s1.getEffectivePriority() == s2.getEffectivePriority()) {
				return Long.compare(s1.timeWaiting, s2.timeWaiting);
			}

			if (s1.getEffectivePriority() < s2.getEffectivePriority()) {
				return 1;
			} else {
				return -1;
			}
		}
	}
	/**
	 * A <tt>ThreadQueue</tt> that sorts threads by priority.
	 */
	protected class PriorityQueue extends ThreadQueue {
		/**
		 * <tt>true</tt> if this queue should transfer priority from waiting
		 * threads to the owning thread.
		 */
		public boolean transferPriority;
		public long id;
		private final java.util.PriorityQueue<KThread> pq;

		private KThread owner;
		PriorityQueue(boolean transferPriority) {
			this.transferPriority = transferPriority;
			this.id = PriorityScheduler.id++;
			pq = new java.util.PriorityQueue<>(new PriorityComparator());
			this.owner = null;
		}

		public void waitForAccess(KThread thread) {
			Lib.assertTrue(Machine.interrupt().disabled());
			if (pq.isEmpty()) {
				this.acquire(thread);
			} else {
				pq.add(thread);
				getThreadState(thread).waitForAccess(this);
			}
		}

		public void adjustPriority(KThread thread) {
			// a thread has changed its priority
			// due to java.util.PriorityQueue's design, we need to remove it and add it back

			this.pq.remove(thread);
			this.pq.add(thread);
		}
		public void acquire(KThread thread) {
			Lib.assertTrue(Machine.interrupt().disabled());
			this.owner = thread;
			getThreadState(thread).acquire(this);
		}

		public KThread nextThread() {
			Lib.assertTrue(Machine.interrupt().disabled());
			getThreadState(owner).release(this);
			KThread next = pq.poll();
			this.owner = next;
			getThreadState(next).acquire(this);

			return next;
		}

		/**
		 * Return the next thread that <tt>nextThread()</tt> would return,
		 * without modifying the state of this queue.
		 *
		 * @return	the next thread that <tt>nextThread()</tt> would
		 *		return.
		 */
		protected ThreadState pickNextThread() {
			// implement me
            assert pq.peek() != null;
            return (ThreadState) pq.peek().schedulingState;
		}

		public void print() {
			Lib.assertTrue(Machine.interrupt().disabled());
			System.out.println(this.pq);
		}

	}
	/**
	 * The scheduling state of a thread. This should include the thread's
	 * priority, its effective priority, any objects it owns, and the queue
	 * it's waiting for, if any.
	 *
	 * @see	nachos.threads.KThread#schedulingState
	 */
	protected class ThreadState {
		/** The thread with which this object is associated. */
		protected KThread thread;
		/** The priority of the associated thread. */
		/* the tail of the queue represents the original priority
		 * while the end is the stack of donated priorities from different threads
		 */
		protected LinkedList<Integer> effectivePriority;

		// the longest waiting thread gets the queue if priority of threads are the same
		protected long timeWaiting;

		// the queues that this thread owns, threads in the queues
		// are not actually in the queue
		protected HashMap<Long, PriorityQueue> ownedLocks;

		// the queues that prevent this thread from waking up
		// if we are donating priority, we need to recursively go through here
		protected HashMap<Long, PriorityQueue> waitingLocks;
		/**
		 * Allocate a new <tt>ThreadState</tt> object and associate it with the
		 * specified thread.
		 *
		 * @param	thread	the thread this state belongs to.
		 */
		public ThreadState(KThread thread) {
			this.thread = thread;
			ownedLocks = new HashMap<>();
			waitingLocks = new HashMap<>();
			effectivePriority = new LinkedList<>();
			setPriority(priorityDefault);
			effectivePriority.add(priorityDefault);
		}

		/**
		 * Return the priority of the associated thread.
		 *
		 * @return	the priority of the associated thread.
		 */
		public int getPriority() {
			return this.effectivePriority.getFirst();
		}

		/**
		 * Return the effective priority of the associated thread.
		 * The last thread represents the greatest priority.
		 * @return	the effective priority of the associated thread.
		 */
		public int getEffectivePriority() {
			return this.effectivePriority.getLast();
		}

		/**
		 * Set the priority of the associated thread to the specified value.
		 *
		 * @param	priority	the new priority.
		 */
		public void setPriority(int priority) {
			if (this.getPriority() == priority)
				return;

			this.effectivePriority.set(0, priority);

			int localMax = PriorityScheduler.priorityMinimum;
			for (PriorityQueue queue : this.ownedLocks.values()) {
				queue.adjustPriority(this.thread);
				localMax = Math.max(localMax, queue.pickNextThread().getPriority());
			}

			for (PriorityQueue queue : this.waitingLocks.values()) {
				queue.adjustPriority(this.thread);
			}

//			if (localMax > this.priority && KThread.currentThread() == this.thread) {
//				KThread._yield();
//			}


		}

		/**
		 * Called when <tt>waitForAccess(thread)</tt> (where <tt>thread</tt> is
		 * the associated thread) is invoked on the specified priority queue.
		 * The associated thread is therefore waiting for access to the
		 * resource guarded by <tt>waitQueue</tt>. This method is only called
		 * if the associated thread cannot immediately obtain access.
		 *
		 * @param	waitQueue	the queue that the associated thread is
		 *				now waiting on.
		 *
		 * @see	nachos.threads.ThreadQueue#waitForAccess
		 */
		public void waitForAccess(PriorityQueue waitQueue) {
			this.timeWaiting = Machine.timer().getTime();
			this.waitingLocks.put(waitQueue.id, waitQueue);
			// donate our priority if we are waiting for a thread that has lower priority that us
			if (this.getPriority() > getThreadState(waitQueue.owner).getEffectivePriority()) {
				this.resolveDonation(this.getPriority(), waitQueue.owner);
			}

		}

		public void resolveDonation(int toDonate, KThread other) {
			ThreadState otherState = getThreadState(other);
			if (this.getPriority() > otherState.getEffectivePriority()) {
				// donate the thread priority
				otherState.effectivePriority.push(toDonate);
				// donate priority to the threads that other is waiting for
				for (PriorityQueue queue : otherState.waitingLocks.values()) {
					otherState.resolveDonation(toDonate, queue.owner);
				}

				otherState.effectivePriority.pop();
			}
		}
		/**
		 * Called when the associated thread has acquired access to whatever is
		 * guarded by <tt>waitQueue</tt>. This can occur either as a result of
		 * <tt>acquire(thread)</tt> being invoked on <tt>waitQueue</tt> (where
		 * <tt>thread</tt> is the associated thread), or as a result of
		 * <tt>nextThread()</tt> being invoked on <tt>waitQueue</tt>.
		 *
		 * @see	nachos.threads.ThreadQueue#acquire
		 * @see	nachos.threads.ThreadQueue#nextThread
		 */
		public void acquire(PriorityQueue waitQueue) {
			ownedLocks.put(waitQueue.id, waitQueue);
            this.waitingLocks.remove(waitQueue.id);
		}

		public void release(PriorityQueue priorityQueue) {
			this.ownedLocks.remove(priorityQueue.id);
		}
	}

	/**
     * Allocate a new priority scheduler.
     */
    public PriorityScheduler() {
    }
    
    /**
     * Allocate a new priority thread queue.
     *
     * @param	transferPriority	<tt>true</tt> if this queue should
     *					transfer priority from waiting threads
     *					to the owning thread.
     * @return	a new priority thread queue.
     */
	public ThreadQueue newThreadQueue(boolean transferPriority) {
		return new PriorityQueue(transferPriority);
	}

	public int getPriority(KThread thread) {
		Lib.assertTrue(Machine.interrupt().disabled());

		return getThreadState(thread).getPriority();
	}

	public int getEffectivePriority(KThread thread) {
		Lib.assertTrue(Machine.interrupt().disabled());

		return getThreadState(thread).getEffectivePriority();
	}

	public void setPriority(KThread thread, int priority) {
		Lib.assertTrue(Machine.interrupt().disabled());

		Lib.assertTrue(priority >= priorityMinimum &&
				priority <= priorityMaximum);


		getThreadState(thread).setPriority(priority);
	}

	public boolean increasePriority() {
		boolean intStatus = Machine.interrupt().disable();

		KThread thread = KThread.currentThread();

		int priority = getPriority(thread);
		if (priority == priorityMaximum)
			return false;

		setPriority(thread, priority+1);

		Machine.interrupt().restore(intStatus);
		return true;
	}

	public boolean decreasePriority() {
		boolean intStatus = Machine.interrupt().disable();

		KThread thread = KThread.currentThread();

		int priority = getPriority(thread);
		if (priority == priorityMinimum)
			return false;

		setPriority(thread, priority-1);

		Machine.interrupt().restore(intStatus);
		return true;
	}

    /**
     * Return the scheduling state of the specified thread.
     *
     * @param	thread	the thread whose scheduling state to return.
     * @return	the scheduling state of the specified thread.
     */
	protected ThreadState getThreadState(KThread thread) {
		if (thread.schedulingState == null)
			thread.schedulingState = new ThreadState(thread);

		return (ThreadState) thread.schedulingState;
	}


}
