from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status, generics, permissions
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework.generics import ListAPIView, get_object_or_404
from rest_framework.pagination import PageNumberPagination
from rest_framework.exceptions import ValidationError, PermissionDenied
from django.db.models import Q
from django.utils import timezone
from django.http import JsonResponse

from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from django.utils.html import strip_tags

from .models import Property, SavedProperty, MeetingRequest, Notification, CustomUser, EventPlace, EventBooking
from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    UserSerializer,
    UpdateProfileSerializer,
    PropertySerializer,
    PropertyCreateSerializer,
    SavedPropertySerializer,
    MeetingRequestSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    NotificationSerializer,
    NotificationMarkReadSerializer,
    AnnouncementSerializer,
    EventPlaceSerializer,
    EventPlaceCreateUpdateSerializer,
    EventBookingSerializer,
)
def home(request):
    return JsonResponse({"status": "ok", "message": "API is running"})



def get_tokens(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        tokens = get_tokens(user)
        return Response({
            "user": UserSerializer(user, context={"request": request}).data,
            "tokens": tokens
        }, status=status.HTTP_201_CREATED)

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        tokens = get_tokens(user)
        return Response({
            "user": UserSerializer(user, context={"request": request}).data,
            "tokens": tokens
        }, status=status.HTTP_200_OK)

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Logout successful"}, status=status.HTTP_205_RESET_CONTENT)
        except KeyError:
            return Response({"error": "Refresh token required"}, status=status.HTTP_400_BAD_REQUEST)
        except TokenError:
            return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

class UserDashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({
            "user": UserSerializer(request.user, context={"request": request}).data
        }, status=status.HTTP_200_OK)

class UpdateUserView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        serializer = UpdateProfileSerializer(request.user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({
            "message": "Profile updated successfully",
            "user": UserSerializer(user, context={"request": request}).data
        }, status=status.HTTP_200_OK)

class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        try:
            user = get_user_model().objects.get(email=email)
        except get_user_model().DoesNotExist:
            return Response(
                {"detail": "If an account with that email exists, a password reset link has been sent."},
                status=status.HTTP_200_OK
            )

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        reset_url = f"{settings.FRONTEND_URL}/reset-password-confirm/{uid}/{token}/"

        context = {
            'user': user,
            'reset_url': reset_url,
            'site_name': settings.SITE_NAME,
            'year': timezone.now().year,
        }

        email_subject = f"Password Reset Request for {settings.SITE_NAME}"

        html_message = render_to_string('email/password_reset_email.html', context)
        plain_message = strip_tags(html_message)

        email_message = EmailMultiAlternatives(
            email_subject,
            plain_message,
            settings.DEFAULT_FROM_EMAIL,
            [email]
        )

        email_message.attach_alternative(html_message, "text/html")

        try:
            email_message.send(fail_silently=False)
        except Exception as e:
            print(f"Error sending email: {e}")
            return Response(
                {"detail": "Failed to send password reset email. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        return Response(
            {"detail": "If an account with that email exists, a password reset link has been sent."},
            status=status.HTTP_200_OK
        )

class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, uidb64, token):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        new_password = serializer.validated_data['new_password']

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = get_user_model().objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            user.set_password(new_password)
            user.save()
            return Response(
                {"detail": "Password has been reset successfully."},
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {"detail": "The reset link is invalid or has expired."},
                status=status.HTTP_400_BAD_REQUEST
            )

class CreatePropertyView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PropertyCreateSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        property_obj = serializer.save()
        return Response({
            "message": "Property listed successfully",
            "property": PropertySerializer(property_obj, context={"request": request}).data
        }, status=status.HTTP_201_CREATED)
class PropertyPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100

class ListAllPropertiesView(generics.ListAPIView):
    queryset = Property.objects.all().order_by('-created_at')
    serializer_class = PropertySerializer
    permission_classes = [permissions.AllowAny]
    pagination_class = PropertyPagination

    def get_serializer_context(self):
        return {"request": self.request}
class ListUserPropertiesView(generics.ListAPIView):
    serializer_class = PropertySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Property.objects.filter(user=self.request.user).order_by('-created_at')

    def get_serializer_context(self):
        return {"request": self.request}

class PropertyDetailView(generics.RetrieveAPIView):
    queryset = Property.objects.all()
    serializer_class = PropertySerializer
    permission_classes = [permissions.AllowAny]
    lookup_field = 'id'

    def get_serializer_context(self):
        return {"request": self.request}

class UpdatePropertyView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        try:
            property_obj = Property.objects.get(id=pk, user=request.user)
        except Property.DoesNotExist:
            return Response({"detail": "Property not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)

        serializer = PropertyCreateSerializer(property_obj, data=request.data, partial=True, context={"request": request})
        serializer.is_valid(raise_exception=True)
        updated_property = serializer.save()
        return Response({
            "message": "Property updated successfully",
            "property": PropertySerializer(updated_property, context={"request": request}).data
        }, status=status.HTTP_200_OK)

class UpdatePropertyStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        status_choice = request.data.get("status")
        valid_statuses = ["Active", "Pending", "Inactive"]
        if status_choice not in valid_statuses:
            return Response({"error": "Invalid status value"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            property_obj = Property.objects.get(id=pk, user=request.user)
            property_obj.status = status_choice
            property_obj.save()
            return Response({"message": f"Status updated to {status_choice}"}, status=status.HTTP_200_OK)
        except Property.DoesNotExist:
            return Response({"detail": "Property not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)

class DeletePropertyView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        try:
            property_obj = Property.objects.get(id=pk, user=request.user)
            property_obj.delete()
            return Response({"message": "Property deleted successfully"}, status=status.HTTP_200_OK)
        except Property.DoesNotExist:
            return Response({"detail": "Property not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)

class SimilarPropertiesView(APIView):
    def get(self, request, pk):
        try:
            current_property = Property.objects.get(pk=pk)
        except Property.DoesNotExist:
            return Response({"detail": "Property not found."}, status=status.HTTP_404_NOT_FOUND)

        similar = Property.objects.filter(
            property_type__iexact=current_property.property_type,
            location__iexact=current_property.location
        ).exclude(pk=pk).distinct()

        if not similar.exists():
            similar = Property.objects.filter(
                Q(property_type__iexact=current_property.property_type) |
                Q(location__iexact=current_property.location)
            ).exclude(pk=pk).distinct()

        if not similar.exists():
            similar = Property.objects.filter(
                property_type__iexact=current_property.property_type
            ).exclude(pk=pk).distinct()

        serializer = PropertySerializer(similar[:6], many=True, context={"request": request})
        return Response(serializer.data)

class FeaturedPropertyPagination(PageNumberPagination):
    page_size = 10

class FeaturedPropertiesView(ListAPIView):
    queryset = Property.objects.all().order_by('-created_at')
    serializer_class = PropertySerializer
    pagination_class = FeaturedPropertyPagination

    def get_serializer_context(self):
        return {"request": self.request}

class SearchPropertiesView(ListAPIView):
    serializer_class = PropertySerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        query = self.request.query_params.get("query", "").strip()
        location = self.request.query_params.get("location")
        type_ = self.request.query_params.get("type")  # buy/rent
        furnished = self.request.query_params.get("furnished")
        property_types = self.request.query_params.getlist("property_type")  # multi
        min_price = self.request.query_params.get("min_price")
        max_price = self.request.query_params.get("max_price")
        bedrooms = self.request.query_params.get("bedrooms")
        bathrooms = self.request.query_params.get("bathrooms")
        ordering = self.request.query_params.get("ordering", "newest")

        filters = Q()

        if query:
            try:
                query_price = int(query)
            except ValueError:
                query_price = None

            filters |= (
                Q(title__icontains=query) |
                Q(location__icontains=query) |
                Q(description__icontains=query) |
                Q(contact_name__icontains=query) |
                Q(property_type__icontains=query) |
                Q(furnished__icontains=query) |
                Q(type__icontains=query) |
                Q(bedrooms__icontains=query) |
                Q(bathrooms__icontains=query)
            )

            if query_price:
                filters |= Q(price__gte=query_price - 10000, price__lte=query_price + 10000)

        if location:
            filters &= Q(location__icontains=location)
        if type_:
            filters &= Q(type__iexact=type_)
        if furnished:
            filters &= Q(furnished__iexact=furnished)
        if property_types:
            filters &= Q(property_type__in=property_types)
        if bedrooms:
            filters &= Q(bedrooms=bedrooms)
        if bathrooms:
            filters &= Q(bathrooms=bathrooms)
        if min_price and max_price:
            filters &= Q(price__gte=min_price, price__lte=max_price)
        elif min_price:
            filters &= Q(price__gte=min_price)
        elif max_price:
            filters &= Q(price__lte=max_price)

        qs = Property.objects.filter(filters)

        if ordering == "price_low":
            qs = qs.order_by("price")
        elif ordering == "price_high":
            qs = qs.order_by("-price")
        else:
            qs = qs.order_by("-created_at")

        return qs

    def get_serializer_context(self):
        return {"request": self.request}

class SavePropertyView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        property_obj = Property.objects.filter(id=pk).first()
        if not property_obj:
            return Response({"detail": "Property not found"}, status=status.HTTP_404_NOT_FOUND)

        saved, created = SavedProperty.objects.get_or_create(user=request.user, property=property_obj)
        if not created:
            return Response({"detail": "Already saved"}, status=status.HTTP_200_OK)

        return Response({"message": "Property saved"}, status=status.HTTP_201_CREATED)

class UnsavePropertyView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        try:
            saved = SavedProperty.objects.get(user=request.user, property_id=pk)
            saved.delete()
            return Response({"message": "Property unsaved"}, status=status.HTTP_200_OK)
        except SavedProperty.DoesNotExist:
            return Response({"detail": "Saved property not found"}, status=status.HTTP_404_NOT_FOUND)

class ListSavedPropertiesView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = SavedPropertySerializer

    def get_queryset(self):
        return SavedProperty.objects.filter(user=self.request.user).order_by('-saved_at')

    def get_serializer_context(self):
        return {"request": self.request}

class CreateMeetingRequestView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        data = request.data.copy()
        data["property_id"] = pk
        serializer = MeetingRequestSerializer(data=data, context={"request": request})

        serializer.is_valid(raise_exception=True)
        meeting = serializer.save()

        Notification.objects.create(
            user=meeting.property.user,
            message=f"New meeting request for your property '{meeting.property.title}' from {request.user.name}.",
            notification_type='meeting_request',
            related_object_id=meeting.id
        )

        return Response({
            "message": "Meeting request created successfully",
            "meeting": MeetingRequestSerializer(meeting, context={"request": request}).data
        }, status=status.HTTP_201_CREATED)

class ListPropertyOwnerMeetingRequestsView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = MeetingRequestSerializer

    def get_queryset(self):
        return MeetingRequest.objects.filter(property__user=self.request.user).order_by('-requested_at')

    def get_serializer_context(self):
        return {"request": self.request}

class ListUserCreatedMeetingRequestsView(ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = MeetingRequestSerializer

    def get_queryset(self):
        return MeetingRequest.objects.filter(user=self.request.user).order_by('-requested_at')

    def get_serializer_context(self):
        return {"request": self.request}

class UpdateMeetingStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        try:
            meeting = MeetingRequest.objects.get(pk=pk)
        except MeetingRequest.DoesNotExist:
            return Response({"detail": "Meeting request not found."}, status=status.HTTP_404_NOT_FOUDN)

        if meeting.property.user != request.user:
            raise PermissionDenied("You do not own this property or are not authorized to update this meeting.")

        status_choice = request.data.get("status")
        valid_statuses = ["pending", "accepted", "rejected", "completed"]
        if status_choice not in valid_statuses:
            return Response({"error": "Invalid status"}, status=status.HTTP_400_BAD_REQUEST)

        if meeting.status in ["completed", "rejected"] and status_choice not in ["completed", "rejected"]:
            return Response({"detail": f"This meeting request is already {meeting.status} and cannot be changed."}, status=status.HTTP_400_BAD_REQUEST)

        meeting.status = status_choice
        meeting.save()

        Notification.objects.create(
            user=meeting.user,
            message=f"Your meeting request for '{meeting.property.title}' was {status_choice}.",
            notification_type='meeting_response',
            related_object_id=meeting.id
        )

        return Response({"message": f"Meeting status updated to {status_choice}"}, status=status.HTTP_200_OK)

class AnnouncementCreateView(generics.CreateAPIView):
    serializer_class = AnnouncementSerializer
    permission_classes = [permissions.IsAdminUser]

    def perform_create(self, serializer):
        announcement_message = serializer.validated_data['message']

        users = CustomUser.objects.filter(is_active=True)

        for user in users:
            Notification.objects.create(
                user=user,
                message=announcement_message,
                notification_type='announcement',
                related_object_id=None
            )

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response({"message": "Announcement sent to all users successfully."}, status=status.HTTP_201_CREATED, headers=headers)

class NotificationListView(generics.ListAPIView):
    serializer_class = NotificationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Notification.objects.filter(user=self.request.user).order_by('-created_at')

class MarkNotificationReadView(generics.UpdateAPIView):
    queryset = Notification.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = NotificationMarkReadSerializer
    lookup_field = 'pk'

    def get_object(self):
        notification = super().get_object()
        if notification.user != self.request.user:
            raise PermissionDenied("You do not have permission to mark this notification as read.")
        return notification

class NotificationDeleteView(generics.DestroyAPIView):
    queryset = Notification.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'pk'

    def get_object(self):
        notification = super().get_object()
        if notification.user != self.request.user:
            raise PermissionDenied("You do not have permission to delete this notification.")
        return notification

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({"message": "Notification deleted successfully."}, status=status.HTTP_204_NO_CONTENT)

class DeleteAllReadNotificationsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        deleted_count, _ = Notification.objects.filter(user=request.user, is_read=True).delete()
        return Response(
            {"message": f"Successfully deleted {deleted_count} read notifications."},
            status=status.HTTP_204_NO_CONTENT
        )

class DeleteAllNotificationsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        deleted_count, _ = Notification.objects.filter(user=request.user).delete()
        return Response(
            {"message": f"Successfully deleted {deleted_count} notifications."},
            status=status.HTTP_204_NO_CONTENT
        )

class EventPlacePagination(PageNumberPagination):
    page_size = 9

class CreateEventPlaceView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = EventPlaceCreateUpdateSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        event_place = serializer.save()
        return Response(
            EventPlaceSerializer(event_place, context={"request": request}).data,
            status=status.HTTP_201_CREATED
        )

class ListEventPlacesView(generics.ListAPIView):
    serializer_class = EventPlaceSerializer
    permission_classes = [AllowAny]
    pagination_class = EventPlacePagination

    def get_queryset(self):
        queryset = EventPlace.objects.all().order_by('-created_at')

        category = self.request.query_params.get('category')
        min_price = self.request.query_params.get('min_price')
        max_price = self.request.query_params.get('max_price')
        available_now = self.request.query_params.get('available_now')
        search_query = self.request.query_params.get('search', '').strip()

        filters = Q()

        if category:
            filters &= Q(category__iexact=category)
        if min_price:
            filters &= Q(price_per_hour__gte=min_price)
        if max_price:
            filters &= Q(price_per_hour__lte=max_price)
        if available_now and available_now.lower() == 'true':
            filters &= Q(is_available_now=True)
        if search_query:
            filters &= (
                Q(name__icontains=search_query) |
                Q(location__icontains=search_query) |
                Q(description__icontains=search_query) |
                Q(contact_name__icontains=search_query)
            )

        queryset = queryset.filter(filters)
        return queryset

    def get_serializer_context(self):
        return {"request": self.request}

class EventPlaceDetailView(generics.RetrieveAPIView):
    queryset = EventPlace.objects.all()
    serializer_class = EventPlaceSerializer
    permission_classes = [AllowAny]
    lookup_field = 'pk'

    def get_serializer_context(self):
        return {"request": self.request}

class UpdateEventPlaceView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        try:
            event_place = EventPlace.objects.get(pk=pk, owner=request.user)
        except EventPlace.DoesNotExist:
            return Response({"detail": "Event place not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)

        serializer = EventPlaceCreateUpdateSerializer(event_place, data=request.data, partial=True, context={"request": request})
        serializer.is_valid(raise_exception=True)
        updated_event_place = serializer.save()
        return Response(
            EventPlaceSerializer(updated_event_place, context={"request": request}).data,
            status=status.HTTP_200_OK
        )

class DeleteEventPlaceView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        try:
            event_place = EventPlace.objects.get(pk=pk, owner=request.user)
            event_place.delete()
            return Response({"message": "Event place deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
        except EventPlace.DoesNotExist:
            return Response({"detail": "Event place not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)

class EventBookingPagination(PageNumberPagination):
    page_size = 6 

class CreateEventBookingView(generics.CreateAPIView):
    serializer_class = EventBookingSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class ListUserEventBookingsView(generics.ListAPIView):
    serializer_class = EventBookingSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = EventBookingPagination 

    def get_queryset(self):
        return EventBooking.objects.filter(user=self.request.user).order_by('-booked_at')

    def get_serializer_context(self):
        return {"request": self.request}

class UpdateEventBookingView(generics.UpdateAPIView):
    queryset = EventBooking.objects.all()
    serializer_class = EventBookingSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'pk'

    def get_object(self):
        booking = super().get_object()
        if booking.event_place.owner == self.request.user or booking.user == self.request.user:
            return booking
        raise PermissionDenied("You do not have permission to update this booking.")

    def update(self, request, *args, **kwargs):
        instance = self.get_object()

        is_owner = instance.event_place.owner == request.user

        data = request.data.copy()

        if not is_owner and 'status' in data:
            del data['status']

        if instance.status in ['completed', 'cancelled'] and not is_owner:
            raise ValidationError("This booking cannot be updated as it is already completed or cancelled.")
        elif instance.status in ['completed', 'cancelled'] and is_owner and 'status' not in data:
            valid_status_change = False
            if 'status' in request.data and request.data['status'] in ['completed', 'cancelled']:
                if request.data['status'] != instance.status:
                    valid_status_change = True
            if not valid_status_change:
                raise ValidationError(f"This booking cannot be updated as it is already {instance.status}. Only status can be changed to 'completed' or 'cancelled' by owner.")

        serializer = self.get_serializer(instance, data=data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        if is_owner:
            Notification.objects.create(
                user=instance.user,
                message=f"Your booking for '{instance.event_place.name}' has been updated by the owner.",
                notification_type='event_booking_update',
                related_object_id=instance.id
            )
        else:
            Notification.objects.create(
                user=instance.event_place.owner,
                message=f"A booking for your event place '{instance.event_place.name}' has been updated by the booker.",
                notification_type='event_booking_update',
                related_object_id=instance.id
            )

        return Response(serializer.data)

class CancelEventBookingView(generics.DestroyAPIView):
    queryset = EventBooking.objects.all()
    permission_classes = [IsAuthenticated]
    lookup_field = 'pk'

    def get_object(self):
        booking = super().get_object()

        if booking.user != self.request.user and booking.event_place.owner != self.request.user:
            raise PermissionDenied("You do not have permission to cancel this booking.")

        if booking.status in ['completed', 'cancelled']:
            raise ValidationError("This booking cannot be cancelled as it is already completed or cancelled.")

        return booking

    def perform_destroy(self, instance):
        instance.status = 'cancelled'
        instance.save()

        if instance.user == self.request.user:
            Notification.objects.create(
                user=instance.event_place.owner,
                message=f"A booking for your event place '{instance.event_place.name}' has been cancelled by the booker.",
                notification_type='event_booking_cancellation',
                related_object_id=instance.id
            )
        elif instance.event_place.owner == self.request.user:
            Notification.objects.create(
                user=instance.user,
                message=f"Your booking for '{instance.event_place.name}' has been cancelled by the owner.",
                notification_type='event_booking_cancellation',
                related_object_id=instance.id
            )

class ListUserListingsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user

        properties_queryset = Property.objects.filter(user=user).order_by('-created_at')
        properties_data = PropertySerializer(properties_queryset, many=True, context={"request": request}).data

        for prop in properties_data:
            prop['listing_type'] = 'property'

        event_places_queryset = EventPlace.objects.filter(owner=user).order_by('-created_at')
        event_places_data = EventPlaceSerializer(event_places_queryset, many=True, context={"request": request}).data

        for event_place in event_places_data:
            event_place['listing_type'] = 'event_place'
            event_place['title'] = event_place.get('name')
            event_place['status'] = 'Active' if event_place.get('is_available_now') else 'Inactive' 

        all_listings = properties_data + event_places_data
        
        all_listings.sort(key=lambda x: x.get('created_at', timezone.now().isoformat()), reverse=True)


        return Response(all_listings, status=status.HTTP_200_OK)
    
class GlobalSearchView(generics.ListAPIView):
    permission_classes = [AllowAny]
    
    def get(self, request, *args, **kwargs):
        query = self.request.query_params.get("q", "").strip()
        
        properties_queryset = Property.objects.none()
        event_places_queryset = EventPlace.objects.none()

        if query:
            # Search for properties
            properties_queryset = Property.objects.filter(
                Q(title__icontains=query) |
                Q(location__icontains=query) |
                Q(description__icontains=query) |
                Q(property_type__icontains=query)
            )

            # Search for event places
            event_places_queryset = EventPlace.objects.filter(
                Q(name__icontains=query) |
                Q(location__icontains=query) |
                Q(description__icontains=query) |
                Q(category__icontains=query)
            )

        # Combine and serialize the results
        properties_data = PropertySerializer(properties_queryset, many=True, context={"request": request}).data
        event_places_data = EventPlaceSerializer(event_places_queryset, many=True, context={"request": request}).data

        for item in properties_data:
            item['listing_type'] = 'property'

        for item in event_places_data:
            item['listing_type'] = 'event_place'
        
        combined_results = sorted(
            properties_data + event_places_data,
            key=lambda x: x.get('created_at', '1970-01-01T00:00:00Z'), # Use a default for sorting
            reverse=True
        )

        return Response(combined_results, status=status.HTTP_200_OK)
