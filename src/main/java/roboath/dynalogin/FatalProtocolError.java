package roboath.dynalogin;

class FatalProtocolError extends Exception implements WithProtocolMessage {
    private final Message protocolMessage;

    public FatalProtocolError(Message protocolMessage, String message) {
        super(message);
        this.protocolMessage = protocolMessage;
    }

    public FatalProtocolError(Message protocolMessage) {
        this(protocolMessage, protocolMessage.getDescription());
    }

    @Override
    public Message getProtocolMessage() {
        return protocolMessage;
    }
}
