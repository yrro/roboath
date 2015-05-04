package roboath.service.protocol;

class ProtocolError extends Exception implements WithProtocolMessage {
    private final Message protocolMessage;

    public ProtocolError(Message protocolMessage, String message) {
        super(message);
        this.protocolMessage = protocolMessage;
    }

    public ProtocolError(Message protocolMessage) {
        this(protocolMessage, protocolMessage.getDescription());
    }

    @Override
    public Message getProtocolMessage() {
        return protocolMessage;
    }
}
