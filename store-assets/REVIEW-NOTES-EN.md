# Google Play Review Notes — Alnoor School 2.0.4

Alnoor School is a role-based school learning and administration app. The reviewer can access four separate portals using the Quick access buttons on the Arabic sign-in screen or the manual credentials provided in APP-ACCESS-EN.md: Administrator, Teacher, Student, and Parent. These are demonstration accounts that use synthetic school records.

For the Student role, Noor Assistant searches the curriculum and lesson content available on the device. The student request is handled by the app's local assistant function and is not sent to the remote assistant API or to a third-party AI provider. This local-only path applies to the Student role; assistant requests from other roles use the school's cloud API.

Account deletion can be requested from the in-app “حذف الحساب” control after sign-in, or through the public web form:
https://baraagpt6-droid.github.io/alnoor-school/delete-account.html

The deletion form records a request for school-administration review. It is a request channel, not an immediate automatic deletion action. School staff must verify and process the request under the school's data-handling procedure.

The public privacy policy is available at:
https://baraagpt6-droid.github.io/alnoor-school/privacy.html
