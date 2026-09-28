package com.agilefreaks.keycloak.anonymous;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.timer.ScheduledTask;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Deletes guests nobody has used in a while, sessions and all.
 *
 * <p>Idleness is measured from the last token refresh, not from the row's age: a realm with
 * long-lived sessions would keep an abandoned guest for as long as its session lasts, while a
 * flat age cap would delete the identity of someone still using the app. A guest that comes back after the cutoff simply gets a new one,
 * exactly as if the app had been reinstalled.
 *
 * <p>A guest that never refreshed at all gets a shorter cutoff: every install mints one, most are
 * never used again, and waiting the full idle window for those would multiply the table by it.
 *
 * <p>Guest tokens can be minted by anyone holding the public client id, so this is the backstop
 * for a user table that otherwise grows with every install.
 */
public class GuestReaperTask implements ScheduledTask {

    private static final Logger LOG = Logger.getLogger(GuestReaperTask.class);

    static final int PAGE_SIZE = 100;
    static final Map<String, String> GUESTS = Map.of(GuestIdentity.ATTR_ANON, "true", UserModel.EXACT, "true");

    /** Session creation and the first token response land a moment apart; no real refresh comes that soon. */
    static final int NEVER_REFRESHED_SLACK_SECONDS = 60;

    private static final int DAY_SECONDS = 24 * 60 * 60;

    private final int maxIdleDays;
    private final int unusedMaxIdleDays;
    private final int batchSize;

    GuestReaperTask(int maxIdleDays, int unusedMaxIdleDays, int batchSize) {
        this.maxIdleDays = maxIdleDays;
        this.unusedMaxIdleDays = unusedMaxIdleDays;
        this.batchSize = batchSize;
    }

    @Override
    public void run(KeycloakSession session) {
        int now = Time.currentTime();
        Cutoffs cutoffs = new Cutoffs(now - maxIdleDays * DAY_SECONDS, now - unusedMaxIdleDays * DAY_SECONDS);
        session.realms().getRealmsStream().forEach(realm -> reap(session, realm, cutoffs));
    }

    private record Cutoffs(int idle, int unused) {
        int latest() {
            return Math.max(idle, unused);
        }
    }

    private void reap(KeycloakSession session, RealmModel realm, Cutoffs cutoffs) {
        // Required: outside a request there is no realm on the context, and the user storage layer
        // dereferences it ("Session not bound to a realm").
        session.getContext().setRealm(realm);

        List<UserModel> idle = new ArrayList<>();
        // Deletions wait until paging is done, so the offsets stay valid for the whole walk.
        for (int first = 0; idle.size() < batchSize; first += PAGE_SIZE) {
            List<UserModel> page = session.users().searchForUserStream(realm, GUESTS, first, PAGE_SIZE).toList();
            page.stream()
                    // A guest cannot have been idle longer than it has existed: no session lookup needed.
                    .filter(guest -> GuestIdentity.createdAt(guest) < cutoffs.latest())
                    .filter(guest -> isIdle(session, realm, guest, cutoffs))
                    .limit(batchSize - idle.size())
                    .forEach(idle::add);
            if (page.size() < PAGE_SIZE) {
                break;
            }
        }

        if (idle.isEmpty()) {
            return;
        }

        int removed = 0;
        for (UserModel guest : idle) {
            try {
                session.sessions().removeUserSessions(realm, guest);
                session.users().removeUser(realm, guest);
                removed++;
            } catch (RuntimeException e) {
                LOG.warnf(e, "could not remove idle guest %s in realm %s", guest.getId(), realm.getName());
            }
        }
        LOG.infof("removed %d idle guest user(s) in realm %s (idle for %d day(s), or %d if never refreshed)",
                removed, realm.getName(), maxIdleDays, unusedMaxIdleDays);
    }

    /** A guest with no session left counts as never refreshed: refreshing needs the session. */
    private static boolean isIdle(KeycloakSession session, RealmModel realm, UserModel guest, Cutoffs cutoffs) {
        int lastRefresh = Stream.concat(
                        session.sessions().getUserSessionsStream(realm, guest),
                        session.sessions().getOfflineUserSessionsStream(realm, guest))
                .filter(s -> s.getLastSessionRefresh() - s.getStarted() > NEVER_REFRESHED_SLACK_SECONDS)
                .mapToInt(UserSessionModel::getLastSessionRefresh)
                .max().orElse(Integer.MIN_VALUE);
        if (lastRefresh == Integer.MIN_VALUE) {
            return GuestIdentity.createdAt(guest) < cutoffs.unused();
        }
        return lastRefresh < cutoffs.idle();
    }

    @Override
    public String getTaskName() {
        return GuestReaperScheduler.TASK_NAME;
    }
}
