package sawtooth.sdk.reactive.common.messaging;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.UnknownFieldSet;
import com.google.protobuf.UnknownFieldSet.Field;
import sawtooth.sdk.protobuf.Message;
import sawtooth.sdk.protobuf.Message.MessageType;
import sawtooth.sdk.protobuf.PingRequest;
import sawtooth.sdk.protobuf.PingResponse;
import sawtooth.sdk.protobuf.TpStateDeleteRequest;
import sawtooth.sdk.protobuf.TpStateDeleteResponse;
import sawtooth.sdk.protobuf.TpStateEntry;
import sawtooth.sdk.protobuf.TpStateGetRequest;
import sawtooth.sdk.protobuf.TpStateGetResponse;
import sawtooth.sdk.protobuf.TpStateSetRequest;
import sawtooth.sdk.protobuf.TpStateSetResponse;
import sawtooth.sdk.reactive.common.utils.FormattingUtils;

/**
 *
 * @author Leonardo T. de Carvalho
 *
 * <a href="https://github.com/CarvalhoLeonardo">GitHub</a>
 * <a href="https://br.linkedin.com/in/leonardocarvalho">LinkedIn</a>
 *
 *      Some of the messages that circulate are basic to Sawtooth,
 *      not bound to any Transaction Processor implementation.
 *
 */
public class CoreMessagesFactory {
  static final int CHECKSTYLE_MAGIC_NUM_ADDRESS_LENGTH = 70;
  static final int CHECKSTYLE_MAGIC_NUM_HEXADECIMAL_BASE = 16;
  static final int CHECKSTYLE_MAGIC_NUM_ID_LENGTH = 22;

  private static final Logger LOGGER = LoggerFactory.getLogger(CoreMessagesFactory.class);
  private static final MessageDigest MESSAGEDIGESTER_512 = null;

  public CoreMessagesFactory() throws NoSuchAlgorithmException {
    this("SHA-512");
  }

  public CoreMessagesFactory(final String digesterAlgo) throws NoSuchAlgorithmException {
    if (digesterAlgo == null || digesterAlgo.isEmpty()) {
      throw new NoSuchAlgorithmException("There is no empty Digester!");
    }
    MESSAGEDIGESTER_512 = MessageDigest.getInstance(digesterAlgo);
  }

  public final Message getPingRequest(final ByteBuffer bbuffer) throws InvalidProtocolBufferException {
    Message newMessage = Message.newBuilder().setContent(createPingRequest(bbuffer).toByteString())
        .setCorrelationId(this.generateId()).setMessageType(MessageType.PING_REQUEST).build();
    return newMessage;
  }

  private PingRequest createPingRequest(final ByteBuffer bbuffer) throws InvalidProtocolBufferException {
    PingRequest.Builder prb = PingRequest.newBuilder();
    if (bbuffer != null && bbuffer.hasRemaining()) {
      prb.setUnknownFields(UnknownFieldSet.newBuilder()
          .addField(0, Field.newBuilder().addLengthDelimited(ByteString.copyFrom(bbuffer)).build())
          .build());
    }
    PingRequest ping = prb.build();

    return ping;
  }

  public final Message getPingResponse(final String correlationId) {
    Message newMessage = Message.newBuilder().setContent(createPingResponse().toByteString())
        .setCorrelationId(correlationId).setMessageType(MessageType.PING_RESPONSE).build();

    return newMessage;
  }

  private PingResponse createPingResponse() {
    PingResponse pong = PingResponse.newBuilder().build();
    return pong;
  }

  public final boolean isValidMerkleAddress(final String merkleAddress) {
    LOGGER.debug("Testing Address {}...", merkleAddress);
    return merkleAddress != null && !merkleAddress.isEmpty()
            && merkleAddress.length() == CHECKSTYLE_MAGIC_NUM_ADDRESS_LENGTH
        && !merkleAddress.toLowerCase().chars().filter(c -> {
          return Character.digit(c, CHECKSTYLE_MAGIC_NUM_HEXADECIMAL_BASE) == -1;
        }).findFirst().isPresent();
  }

  /**
   * generate a random String using the sha-512 algorithm, to correlate sent messages with futures
   *
   * Being random, we dont need to reset() it
   *
   * @return a random String
   */
  protected final String generateId() {
    return FormattingUtils.bytesToHex(MESSAGEDIGESTER_512.digest(
            UUID.randomUUID().toString().getBytes())).substring(0, CHECKSTYLE_MAGIC_NUM_ID_LENGTH);
  }


  public final Map<String, ByteString> getStateResponse(final Message mesg) {

    Map<String, ByteString> result = new HashMap<>();
    TpStateGetResponse.Builder parser = TpStateGetResponse.newBuilder();
    try {
      parser.mergeFrom(mesg.getContent()).build().getEntriesList().forEach(tpste -> {
        result.put(tpste.getAddress(), tpste.getData());
      });
    } catch (InvalidProtocolBufferException e) {
      e.printStackTrace();
    }

    return result;
  }

  private TpStateGetResponse createTpStateGetResponse(final List<TpStateEntry> entries) {
    Optional<TpStateEntry> wrongAddressEntry =
        entries.stream().filter(str -> !isValidMerkleAddress(str.getAddress())).findFirst();
    if (wrongAddressEntry.isPresent()) {
      LOGGER.error("Invalid Address for TpStateEntry : " + wrongAddressEntry.get().getAddress());
      return null;
    }

    TpStateGetResponse.Builder reqBuilder = TpStateGetResponse.newBuilder();
    reqBuilder.addAllEntries(entries);
    return reqBuilder.build();

  }

  public final Message getStateRequest(final List<String> addresses) {
    Message newMessage = Message.newBuilder()
        .setContent(createTpStateGetRequest(addresses).toByteString())
        .setCorrelationId(generateId()).setMessageType(MessageType.TP_STATE_GET_REQUEST).build();

    return newMessage;
  }

  private TpStateGetRequest createTpStateGetRequest(final List<String> addresses) {
    Optional<String> wrongAddress =
        addresses.stream().filter(str -> !isValidMerkleAddress(str)).findFirst();
    if (wrongAddress.isPresent()) {
      LOGGER.error("Invalid Address " + wrongAddress.get());
      return null;
    }

    TpStateGetRequest.Builder reqBuilder = TpStateGetRequest.newBuilder();
    reqBuilder.addAllAddresses(addresses);
    return reqBuilder.build();

  }

  public final Message getSetStateRequest(final String contextId,
      final List<java.util.Map.Entry<String, ByteString>> addressDataMap) {
    Message newMessage = Message.newBuilder()
        .setContent(createTpStateSetRequest(contextId, addressDataMap).toByteString())
        .setCorrelationId(generateId()).setMessageType(MessageType.TP_STATE_SET_REQUEST).build();

    return newMessage;
  }

  private TpStateSetRequest createTpStateSetRequest(final String contextId,
      final List<java.util.Map.Entry<String, ByteString>> addressDataMap) {

    ArrayList<TpStateEntry> entryArrayList = new ArrayList<TpStateEntry>();
    for (Map.Entry<String, ByteString> entry : addressDataMap) {
      TpStateEntry ourTpStateEntry =
          TpStateEntry.newBuilder().setAddress(entry.getKey()).setData(entry.getValue()).build();
      entryArrayList.add(ourTpStateEntry);
    }

    Optional<TpStateEntry> wrongAddress =
        entryArrayList.stream().filter(str -> !isValidMerkleAddress(str.getAddress())).findFirst();
    if (wrongAddress.isPresent()) {
      LOGGER.error("Invalid Address " + wrongAddress.get().getAddress());
      return null;
    }

    TpStateSetRequest.Builder reqBuilder = TpStateSetRequest.newBuilder().setContextId(contextId);

    TpStateEntry.Builder stateBuilder = TpStateEntry.newBuilder();

    reqBuilder.addAllEntries(entryArrayList.stream().sequential().map(es -> {
      stateBuilder.clear();
      stateBuilder.setAddress(es.getAddress());
      stateBuilder.setData(es.getData());
      return stateBuilder.build();
    }).collect(Collectors.toList()));

    return reqBuilder.build();

  }

  public final List<String> parseStateSetResponse(final Message respMesg)
      throws InvalidProtocolBufferException {
    TpStateSetResponse parsedExp = TpStateSetResponse.parseFrom(respMesg.getContent());

    return parsedExp.getAddressesList().asByteStringList().stream().map(ead -> {
      return ead.toString(StandardCharsets.UTF_8);
    }).collect(Collectors.toList());

  }

  private TpStateDeleteRequest createTpStateDeleteRequest(final List<String> addresses) {
    Optional<String> wrongAddress =
        addresses.stream().filter(str -> !isValidMerkleAddress(str)).findFirst();
    if (wrongAddress.isPresent()) {
      LOGGER.error("Invalid Address " + wrongAddress.get());
      return null;
    }

    TpStateDeleteRequest.Builder reqBuilder = TpStateDeleteRequest.newBuilder();

    reqBuilder.addAllAddresses(addresses);
    return reqBuilder.build();
  }

  private TpStateDeleteResponse createTpStateDeleteResponse(final List<String> addresses) {
    Optional<String> wrongAddress =
        addresses.stream().filter(str -> !isValidMerkleAddress(str)).findFirst();
    if (wrongAddress.isPresent()) {
      LOGGER.error("Invalid Address " + wrongAddress.get());
      return null;
    }

    TpStateDeleteResponse.Builder reqBuilder = TpStateDeleteResponse.newBuilder();

    reqBuilder.addAllAddresses(addresses);
    return reqBuilder.build();
  }
}
