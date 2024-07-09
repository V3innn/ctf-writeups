# DownUnderCTF 2024 
## OSINT - Bridget Lives 
`easy`
![Alt Text](../img/DownUnderCTF_Pic.png)
## Start searching

We were given a photo taken from a building that we must find to submit it as the flag.
In the photo we are seeing a big bridge over some river.

If you know geolocation or the name of the bridge you have a big advantage finding the building.
But if you are like me that I'm not knowing, **Yandex** or **Google Lens** is the solution to our problem xD

**Google Lens** work better this time and after a little scroll down we saw a bridge similar to that we are looking for.
link: https://structurae.net/en/structures/robertson-bridge/media
![[google_lens_explained.png]]
So now we are knowing the name of the bridge: **Robertson Bridge**, and the country that belongs to: Singapore

That's great news. We go straight out for google maps to start searching the area for the building.
The original photo (just marked to explain my thinking): 
![[bridget_explained_4.png]]

We can tell that the building is for sure in the south side of the bridge for many reasons. Obviously we can see **stairs** only in one side of the bridge and not in the other, markdown with blue color.
Two more facts is that we can see a **rectangle** in the same spot as the original photo, markdown with yellow and if we look up in the Street View mode we can see the difference between the length of the 4 iron pipes of the bridge, markdown with red and purple.
![[google_maps_3D_explained.png]]

You can tell that the photo was taken from a very high altitude with the point that looks down to the bridge and the river. So it has to be this building
![[building_that_photo_taken.png]]

We just navigate to find the name of the building but we only see some restaurants. We took a few more steps on the left path and we eventually found it!!!
![[building_found.png]]

So the **flag** is: `DUCTF{Four_Points}`
