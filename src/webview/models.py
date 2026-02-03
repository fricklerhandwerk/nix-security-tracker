from typing import Any

from django.contrib.auth.models import User
from django.contrib.postgres import fields
from django.db import models, transaction
from django.db.models.signals import post_save
from django.dispatch import receiver


class Notification(models.Model):
    """
    Notification to appear in the notification center of a user.
    """

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="notifications"
    )
    # FIXME(@fricklerhandwerk): I find it questionable whether notifications should be character blobs.
    title = models.CharField(max_length=255)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def toggle_read(self) -> int:
        """
        Toggle a notification's read status and update user's unread counter.

        Returns the new unread counter.
        """
        profile = self.user.profile
        with transaction.atomic():
            self.is_read = not self.is_read
            self.save(update_fields=["is_read"])

            # FIXME(@fricklerhandwerk): [tag:count-notifications]: We may want to simply `.count()` on every full page instead of risking permanent inconsistency arising from unforseen edge cases.
            # The rationale by @florentc for denormalising was a performance consideration, but
            # - the difference will likely not be noticeable with <100 users
            # - it needs measurement in any case
            # - may resolve itself eventually as we increasingly avoid page reloads
            if not self.is_read:
                profile.unread_notifications_count += 1
            else:
                profile.unread_notifications_count = max(
                    0, profile.unread_notifications_count - 1
                )
            profile.save(update_fields=["unread_notifications_count"])

        return profile.unread_notifications_count


class Profile(models.Model):
    """
    Profile associated to a user, storing extra non-auth-related data such as
    active issue subscriptions.
    """

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    unread_notifications_count = models.PositiveIntegerField(default=0)
    package_subscriptions = fields.ArrayField(
        models.CharField(max_length=255),
        default=list,
        blank=True,
        help_text="Package attribute names this user has subscribed to manually (e.g., 'firefox', 'chromium')",
    )
    auto_subscribe_to_maintained_packages = models.BooleanField(
        default=True,
        help_text="Automatically subscribe to notifications for packages this user maintains",
    )

    def create_notification(
        self, title: str, message: str, is_read: bool = False
    ) -> Notification:
        """Create a notification and update the user's unread counter."""
        notification = Notification.objects.create(
            user=self.user, title=title, message=message, is_read=is_read
        )

        # Update counter if notification is unread
        if not is_read:
            self.unread_notifications_count += 1
            self.save(update_fields=["unread_notifications_count"])

        return notification

    def mark_all_read_for_user(self) -> int:
        """Mark all notifications as read for a user and reset counter. Returns count of notifications marked."""
        unread = Notification.objects.filter(user=self.user, is_read=False)
        unread_count = unread.count()

        if unread_count > 0:
            unread.update(is_read=True)

            self.unread_notifications_count = 0
            self.save(update_fields=["unread_notifications_count"])

        return unread_count

    def clear_read_for_user(self) -> int:
        """Delete all read notifications for a user. Counter should remain unchanged."""
        read = Notification.objects.filter(user=self.user, is_read=True)
        count = read.count()

        if count > 0:
            read.delete()

        return count


@receiver(post_save, sender=User)
def create_profile(
    sender: type[User], instance: User, created: bool, **kwargs: Any
) -> None:
    if created:
        Profile.objects.create(user=instance)
