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

/**
 * Deletes guests nobody has used in a while, sessions and all.
 *
 * <p>Idleness is measured from the last token refresh, not from the row's age: the realm's
 * sessions run to 180 days idle and a year long, so waiting for a guest's session to disappear
 * means waiting the better part of a year, while a flat age cap would delete the identity of
 * someone still using the app. A guest that comes back after the cutoff simply gets a new one,
 * exactly as if the app had been reinstalled.
 *
 * <p>Guest tokens can be minted by anyone holding the public client id, so this is the backstop
 * for a user table that otherwise grows with every install.
 */
public class GuestReaperTask implements ScheduledTask {

    private static final Logger LOG = Logger.getLogger(GuestReaperTask.class);

    static final int PAGE_SIZE = 100;
    static final Map<String, String> GUESTS = Map.of(GuestIdentity.ATTR_ANON, "true", UserModel.EXACT, "true");

    private final int maxIdleDays;
    private final int batchSize;

    GuestReaperTask(int maxIdleDays, int batchSize) {
        this.maxIdleDays = maxIdleDays;
        this.batchSize = batchSize;
    }

    @Override
    public void run(KeycloakSession session) {
        int cutoff = Time.currentTime() - (maxIdleDays * 24 * 60 * 60);
        session.realms().getRealmsStream().forEach(realm -> reap(session, realm, cutoff));
    }

    private void reap(KeycloakSession session, RealmModel realm, int cutoff) {
        // Required: outside a request there is no realm on the context, and the user storage layer
        // dereferences it ("Session not bound to a realm").
        session.getContext().setRealm(realm);

        List<UserModel> idle = new ArrayList<>();
        // Deletions wait until paging is done, so the offsets stay valid for the whole walk.
        for (int first = 0; idle.size() < batchSize; first += PAGE_SIZE) {
            List<UserModel> page = session.users().searchForUserStream(realm, GUESTS, first, PAGE_SIZE).toList();
            page.stream()
                    // A guest cannot have been idle longer than it has existed: no session lookup needed.
                    .filter(guest -> GuestIdentity.createdAt(guest) < cutoff)
                    .filter(guest -> lastRefresh(session, realm, guest) < cutoff)
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
        LOG.infof("removed %d idle guest user(s) in realm %s (unused for %d day(s))",
                removed, realm.getName(), maxIdleDays);
    }

    private static int lastRefresh(KeycloakSession session, RealmModel realm, UserModel guest) {
        int online = session.sessions().getUserSessionsStream(realm, guest)
                .mapToInt(UserSessionModel::getLastSessionRefresh).max().orElse(Integer.MIN_VALUE);
        int offline = session.sessions().getOfflineUserSessionsStream(realm, guest)
                .mapToInt(UserSessionModel::getLastSessionRefresh).max().orElse(Integer.MIN_VALUE);
        return Math.max(online, offline);
    }

    @Override
    public String getTaskName() {
        return GuestReaperScheduler.TASK_NAME;
    }
}
