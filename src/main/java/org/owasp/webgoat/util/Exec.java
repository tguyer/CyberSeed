
package org.owasp.webgoat.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.BitSet;


/***************************************************************************************************
 * 
 * 
 * This file is part of WebGoat, an Open Web Application Security Project utility. For details,
 * please see http://www.owasp.org/
 * 
 * Copyright (c) 2002 - 20014 Bruce Mayhew
 * 
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with this program; if
 * not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 * 
 * Getting Source ==============
 * 
 * Source for this application is maintained at https://github.com/WebGoat/WebGoat, a repository for free software
 * projects.
 * 
 * For details, please see http://webgoat.github.io
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created October 28, 2003
 */
public class Exec
{

	/**
	 * Description of the Method
	 * 
	 * @param command
	 *            Description of the Parameter
	 * @param input
	 *            Description of the Parameter
	 * @return Description of the Return Value
	 */
	public static ExecResults execInput(String command, String input)
	{
		return (execOptions(command, input, 0, 0, false));
	}

	/**
	 * Description of the Method
	 * 
	 * @param command
	 *            Description of the Parameter
	 * @return Description of the Return Value
	 */
	public static ExecResults execLazy(String command)
	{
		return (execOptions(command, "", 0, 0, true));
	}

	/*
	 * Execute an OS command and capture the output in an ExecResults. All exceptions are caught and
	 * stored in the ExecResults. @param String command is the OS command to execute @param String
	 * input is piped into the OS command @param int successCode is the expected return code if the
	 * command completes successfully @param int timeout is the number of milliseconds to wait
	 * before interrupting the command @param boolean quit tells the method to exit when there is no
	 * more output waiting
	 */
	/**
	 * Description of the Method
	 * 
	 * @param command
	 *            Description of the Parameter
	 * @param input
	 *            Description of the Parameter
	 * @param successCode
	 *            Description of the Parameter
	 * @param timeout
	 *            Description of the Parameter
	 * @param lazy
	 *            Description of the Parameter
	 * @return Description of the Return Value
	 */
	public static ExecResults execOptions(String[] command, String input, int successCode, int timeout, boolean lazy)
	{
		Process child = null;
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		ByteArrayOutputStream errors = new ByteArrayOutputStream();
		ExecResults results = new ExecResults(Arrays.asList(command).toString(), input, successCode, timeout);
		BitSet interrupted = new BitSet(1);
		boolean lazyQuit = false;
		ThreadWatcher watcher;

		try
		{
			// start the command
			child = Runtime.getRuntime().exec(command);

			// get the streams in and out of the command
			InputStream processIn = child.getInputStream();
			InputStream processError = child.getErrorStream();
			OutputStream processOut = child.getOutputStream();

			// start the clock running
			if (timeout > 0)
			{
				watcher = new ThreadWatcher(child, interrupted, timeout);
				new Thread(watcher).start();
			}

			// Write to the child process' input stream
			if ((input != null) && !input.equals(""))
			{
				try
				{
					processOut.write(input.getBytes());
					processOut.flush();
					processOut.close();
				} catch (IOException e1)
				{
					results.setThrowable(e1);
				}
			}

			// Read from the child process' output stream
			// The process may get killed by the watcher at any time
			int c = 0;

			try
			{
				while (true)
				{
					if (interrupted.get(0) || lazyQuit)
					{
						break;
					}

					// interrupted
					c = processIn.read();

					if (c == -1)
					{
						break;
					}

					// end of stream
					output.write(c);

					if (lazy && (processIn.available() < 1))
					{
						lazyQuit = true;
					}

					// if lazy and nothing then quit (after at least one read)
				}

				processIn.close();
			} catch (IOException e2)
			{
				results.setThrowable(e2);
			} finally
			{
				if (interrupted.get(0))
				{
					results.setInterrupted();
				}

				results.setOutput(output.toString());
			}

			// Read from the child process' error stream
			// The process may get killed by the watcher at any time
			try
			{
				while (true)
				{
					if (interrupted.get(0) || lazyQuit)
					{
						break;
					}

					// interrupted
					c = processError.read();

					if (c == -1)
					{
						break;
					}

					// end of stream
					output.write(c);

					if (lazy && (processError.available() < 1))
					{
						lazyQuit = true;
					}

					// if lazy and nothing then quit (after at least one read)
				}

				processError.close();
			} catch (IOException e3)
			{
				results.setThrowable(e3);
			} finally
			{
				if (interrupted.get(0))
				{
					results.setInterrupted();
				}

				results.setErrors(errors.toString());
			}

			// wait for the return value of the child process.
			if (!interrupted.get(0) && !lazyQuit)
			{
				int returnCode = child.waitFor();
				results.setReturnCode(returnCode);

				if (returnCode != successCode)
				{
					results.setError(ExecResults.BADRETURNCODE);
				}
			}
		} catch (InterruptedException i)
		{
			results.setInterrupted();
		} catch (Throwable t)
		{
			results.setThrowable(t);
		} finally
		{
			if (child != null)
			{
				child.destroy();
			}
		}

		return (results);
	}

	/*
	 * Execute an OS command and capture the output in an ExecResults. All exceptions are caught and
	 * stored in the ExecResults. @param String command is the OS command to execute @param String
	 * input is piped into the OS command @param int successCode is the expected return code if the
	 * command completes successfully @param int timeout is the number of milliseconds to wait
	 * before interrupting the command @param boolean quit tells the method to exit when there is no
	 * more output waiting
	 */
	/**
	 * Description of the Method
	 * 
	 * @param command
	 *            Description of the Parameter
	 * @param input
	 *            Description of the Parameter
	 * @param successCode
	 *            Description of the Parameter
	 * @param timeout
	 *            Description of the Parameter
	 * @param lazy
	 *            Description of the Parameter
	 * @return Description of the Return Value
	 */
	public static ExecResults execOptions(String command, String input, int successCode, int timeout, boolean lazy)
	{
		Process child = null;
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		ByteArrayOutputStream errors = new ByteArrayOutputStream();
		ExecResults results = new ExecResults(command, input, successCode, timeout);
		BitSet interrupted = new BitSet(1);
		boolean lazyQuit = false;
		ThreadWatcher watcher;

		try
		{
			// start the command
			child = Runtime.getRuntime().exec(command);

			// get the streams in and out of the command
			InputStream processIn = child.getInputStream();
			InputStream processError = child.getErrorStream();
			OutputStream processOut = child.getOutputStream();

			// start the clock running
			if (timeout > 0)
			{
				watcher = new ThreadWatcher(child, interrupted, timeout);
				new Thread(watcher).start();
			}

			// Write to the child process' input stream
			if ((input != null) && !input.equals(""))
			{
				try
				{
					processOut.write(input.getBytes());
					processOut.flush();
					processOut.close();
				} catch (IOException e1)
				{
					results.setThrowable(e1);
				}
			}

			// Read from the child process' output stream
			// The process may get killed by the watcher at any time
			int c = 0;

			try
			{
				while (true)
				{
					if (interrupted.get(0) || lazyQuit)
					{
						break;
					}

					// interrupted
					c = processIn.read();

					if (c == -1)
					{
						break;
					}

					// end of stream
					output.write(c);

					if (lazy && (processIn.available() < 1))
					{
						lazyQuit = true;
					}

					// if lazy and nothing then quit (after at least one read)
				}

				processIn.close();
			} catch (IOException e2)
			{
				results.setThrowable(e2);
			} finally
			{
				if (interrupted.get(0))
				{
					results.setInterrupted();
				}

				results.setOutput(output.toString());
			}

			// Read from the child process' error stream
			// The process may get killed by the watcher at any time
			try
			{
				while (true)
				{
					if (interrupted.get(0) || lazyQuit)
					{
						break;
					}

					// interrupted
					c = processError.read();

					if (c == -1)
					{
						break;
					}

					// end of stream
					output.write(c);

					if (lazy && (processError.available() < 1))
					{
						lazyQuit = true;
					}

					// if lazy and nothing then quit (after at least one read)
				}

				processError.close();
			} catch (IOException e3)
			{
				results.setThrowable(e3);
			} finally
			{
				if (interrupted.get(0))
				{
					results.setInterrupted();
				}

				results.setErrors(errors.toString());
			}

			// wait for the return value of the child process.
			if (!interrupted.get(0) && !lazyQuit)
			{
				int returnCode = child.waitFor();
				results.setReturnCode(returnCode);

				if (returnCode != successCode)
				{
					results.setError(ExecResults.BADRETURNCODE);
				}
			}
		} catch (InterruptedException i)
		{
			results.setInterrupted();
		} catch (Throwable t)
		{
			results.setThrowable(t);
		} finally
		{
			if (child != null)
			{
				child.destroy();
			}
		}

		return (results);
	}

	/**
	 * Description of the Method
	 * 
	 * @param command
	 *            Description of the Parameter
	 * @return Description of the Return Value
	 */
	public static ExecResults execSimple(String[] command)
	{
		return (execOptions(command, "", 0, 0, false));
	}

	/**
	 * Description of the Method
	 * 
	 * @param command
	 *            Description of the Parameter
	 * @return Description of the Return Value
	 */
	public static ExecResults execSimple(String command)
	{
		return (execOptions(command, "", 0, 0, false));
	}

	/**
	 * Description of the Method
	 * 
	 * @param command
	 *            Description of the Parameter
	 * @param args
	 *            Description of the Parameter
	 * @return Description of the Return Value
	 */
	public static ExecResults execSimple(String command, String args)
	{
		return (execOptions(command, args, 0, 0, false));
	}

	/**
	 * Description of the Method
	 * 
	 * @param command
	 *            Description of the Parameter
	 * @param timeout
	 *            Description of the Parameter
	 * @return Description of the Return Value
	 */
	public static ExecResults execTimeout(String command, int timeout)
	{
		return (execOptions(command, "", 0, timeout, false));
	}
}
