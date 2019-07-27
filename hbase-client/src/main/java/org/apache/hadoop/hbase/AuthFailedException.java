package org.apache.hadoop.hbase;

public class AuthFailedException extends MasterNotRunningException
{
   public AuthFailedException(String s) {
        super(s);
    }
}
