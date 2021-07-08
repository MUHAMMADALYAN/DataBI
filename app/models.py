from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth.models import User

# In this web app a Microsoft Advertising user maps a Django web user to a refresh token.

class BingAdsUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.PROTECT)
    refresh_token = models.CharField(max_length=200)

    # def __unicode__(self):              # __unicode__ on Python 2
    #     return self.refresh_token
    def __str__(self):              # __str__ on Python 3
        return self.refresh_token   
