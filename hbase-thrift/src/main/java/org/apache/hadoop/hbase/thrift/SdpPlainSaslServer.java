package org.apache.hadoop.hbase.thrift;

import com.cgws.sdp.auth.plugin.SdpAuthException;
import com.cgws.sdp.auth.plugin.SdpAuthenticator;
import com.cgws.sdp.rpc.portal.UserDoc;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import java.security.Provider;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.Map;

public class SdpPlainSaslServer implements SaslServer {
  public static final Log LOG = LogFactory.getLog(SdpPlainSaslServer.class);

  public static final String SDP_MECHANISM = "PLAIN";
  public static final String SASL_SDP_AUTHCINFO_SEPARATOR = " ";

  boolean isComplete = false;
  String authzId;

  @Override
  public String getMechanismName() {
    return SDP_MECHANISM;
  }

  /**
   *
   * @param response
   * @return
   * @throws SaslException
   */
  @Override
  public byte[] evaluateResponse(byte[] response) throws SaslException {
    /*
     * Message format (from https://tools.ietf.org/html/rfc4616):
     * 
     * message = [authzid] UTF8NUL authcid UTF8NUL passwd authcid = 1*SAFE ; MUST accept up to 255
     * octets authzid = 1*SAFE ; MUST accept up to 255 octets passwd = 1*SAFE ; MUST accept up to
     * 255 octets UTF8NUL = %x00 ; UTF-8 encoded NUL character
     * 
     * SAFE = UTF1 / UTF2 / UTF3 / UTF4 ;; any UTF-8 encoded Unicode character except NUL
     */


    // String[] tokens;
    // try {
    // LOG.info("start authenticate user, input info:"+ new String(response, "UTF-8"));
    //
    // tokens = new String(response, "UTF-8").split("\u0000");
    // } catch (UnsupportedEncodingException e) {
    // throw new SaslException("UTF-8 encoding not supported", e);
    // }
    // if (tokens.length != 3)
    // throw new SaslException("Invalid SASL/SDP response: expected 3 tokens, got " +
    // tokens.length);
    //
    // String authcInfo = tokens[1];


    Deque<String> tokenList = new ArrayDeque<String>();
    StringBuilder messageToken = new StringBuilder();
    for (byte b : response) {
      if (b == 0) {
        tokenList.addLast(messageToken.toString());
        messageToken = new StringBuilder();
      } else {
        messageToken.append((char) b);
      }
    }
    tokenList.addLast(messageToken.toString());

    // validate response
    if (tokenList.size() < 2 || tokenList.size() > 3) {
      throw new SaslException("Invalid SASL/SDP response: expected 3 tokens, got "
          + tokenList.size());
    }

    tokenList.removeLast();
    String authcInfo = tokenList.removeLast();
    String[] authcInfoparts =
        StringUtils.split(authcInfo, SdpPlainSaslServer.SASL_SDP_AUTHCINFO_SEPARATOR);

    if (authcInfo.isEmpty() || !(authcInfoparts.length == 4)) {
      throw new SaslException(
          "Authentication for sdp mechanism failed: sdp auth params not specified.");
    }

    try {
      UserDoc userDoc =
          SdpAuthenticator.getInstance().authenticate(authcInfoparts[0].trim(),
              Long.parseLong(authcInfoparts[1].trim()), Integer.parseInt(authcInfoparts[2].trim()),
              authcInfoparts[3].trim());
      // authenticated user will be used in authenrization
      authzId = userDoc.getName();
      LOG.debug("authenticated user:" + authzId);
    } catch (SdpAuthException e) {
      LOG.warn("authentication failed with sdp mechanism, client params received:" + authcInfo);
      throw new SaslException(e.getMessage());
    }

    LOG.debug("successfully authenticated user " + authzId + " with sdp auth.");

    isComplete = true;
    return new byte[0];
  }

  @Override
  public boolean isComplete() {
    return isComplete;
  }

  @Override
  public String getAuthorizationID() {
    if (!isComplete) {
      throw new IllegalStateException(" SDP SASL Authentication exchange has not completed");
    }
    return authzId;
  }

  @Override
  public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
    if (!isComplete) throw new IllegalStateException("Authentication exchange has not completed");
    return Arrays.copyOfRange(incoming, offset, offset + len);
  }

  @Override
  public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
    if (!isComplete) throw new IllegalStateException("Authentication exchange has not completed");
    return Arrays.copyOfRange(outgoing, offset, offset + len);
  }

  @Override
  public Object getNegotiatedProperty(String propName) {
    if (!isComplete) throw new IllegalStateException("Authentication exchange has not completed");
    return null;
  }

  @Override
  public void dispose() throws SaslException {

  }

  // sasl factory class
  public static class SdpSaslServerFactory implements SaslServerFactory {

    @Override
    public SaslServer createSaslServer(String mechanism, String protocol, String serverName,
        Map<String, ?> props, CallbackHandler cbh) throws SaslException {
      if (SDP_MECHANISM.equalsIgnoreCase(mechanism)) {
        return new SdpPlainSaslServer();
      } else {
        throw new SaslException("Unsupported mechanism,only SDP suported!");
      }
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> props) {
      return new String[] {SDP_MECHANISM};
    }
  }

  // sasl provider class
  public static class SdpSaslServerProvider extends Provider {

    public SdpSaslServerProvider() {

      super("SASL/SDP authentication  server provider", 1.0,
          "sasl server provider");
      super.put("SaslServerFactory." + SDP_MECHANISM,
          SdpSaslServerFactory.class.getName());
    }
  }
}
