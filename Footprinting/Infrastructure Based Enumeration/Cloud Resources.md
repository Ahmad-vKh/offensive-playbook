
The use of cloud, such as [AWS](https://aws.amazon.com/), [GCP](https://cloud.google.com/), [Azure](https://azure.microsoft.com/en-us/) .

all companies want to be able to do their work from anywhere, so they need a central point for all management.
`Amazon` (`AWS`), `Google` (`GCP`), and `Microsoft` (`Azure`) are ideal for this purpose.


starts with the `S3 buckets` (AWS), > which can be accessed without authentication if configured incorrectly.
`blobs` (Azure), `cloud storage` (GCP),
# 1

```shell-session
s3-website-us-west-2.amazonaws.com 10.129.95.250
this indicates very good initial footprint
```


# 2
there are many different ways to find such cloud storage

in google search
```
intext:company-name inrul:amazonaws.com for AWS
intext:company-name inrul:blob.core.windows.net <> for azure
```

# 3

Third-party providers such as [domain.glass](https://domain.glass) can also tell us a lot about the company's infrastructure.



# 4 

Another very useful provider is [GrayHatWarfare](https://buckets.grayhatwarfare.com). We can do many different searches, discover AWS, Azure, and GCP cloud storage, and even sort and filter by file format. Therefore, once we have found them through Google, we can also search for them on GrayHatWarefare and passively discover what files are stored on the given cloud storage.


Many companies also use abbreviations of the company name, which are then used accordingly within the IT infrastructure. Such terms are also part of an excellent approach to discovering new cloud storage from the company. We can also search for files simultaneously to see the files that can be accessed at the same time.

Private and Public SSH Keys Leaked



