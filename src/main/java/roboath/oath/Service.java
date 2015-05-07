package roboath.oath;

import com.google.common.util.concurrent.AbstractIdleService;
import com.lochbridge.oath.otp.HOTPValidationResult;
import com.lochbridge.oath.otp.HOTPValidator;
import com.lochbridge.oath.otp.TOTP;
import lombok.extern.slf4j.Slf4j;
import roboath.Config;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

@Slf4j
public class Service extends AbstractIdleService {
    private final Config config;

    private ConcurrentMap<String, Record> data;

    public Service(Config config) {
        this.config = config;
    }

    @Override
    protected void startUp() throws Exception {
        data = new ConcurrentHashMap<>();
        data.put("sam", Record.builder().mode("HOTP").key(new byte[20]).movingFactor(200L).build());
    }

    @Override
    protected void shutDown() throws Exception {
        // wait for any write requests to terminate
    }

    public boolean validateHOTP(String user, String authcode) {
        Record r = data.get(user);
        if (r == null) {
            log.debug("User not found");
            return false;
        }

        HOTPValidationResult res = HOTPValidator.lookAheadWindow(8)
            .validate(r.getKey(), r.getMovingFactor().intValue(), authcode.length(), authcode);

        data.put(user, r.withMovingFactor(res.getNewMovingFactor()));
        return res.isValid();
    }

    public boolean validateTOTP(String user, String authcode) {
        Record r = data.get(user);
        if (r == null) {
            log.debug("User not found");
            return false;
        }

        TOTP res = TOTP.key(r.getKey())
            .timeStep(TimeUnit.SECONDS.toMillis(30))
            .digits(authcode.length())
            .hmacSha1()
            .build();
        return res.value().equals(authcode);
    }
}
