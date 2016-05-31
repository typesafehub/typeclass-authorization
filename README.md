# Simple Authorization with Type Classes

This is a simple project showing the use of type classes and implicits to provide an authorization framework. 

```scala
val users = Set("jeff", "steve", "mutt")

val steveAndJeffsGroup = new Group(Set("jeff", "steve"))
val muttsOrg = new Organization(admin = "mutt")
val stevesOrg = new Organization(admin = "steve")

for (currentUser <- users) {
  implicit val context = new ExampleSecurityContext(currentUser)
    
  println(s"Is $steveAndJeffsGroup readable by $currentUser? ${Readable(steveAndJeffsGroup)}")
  println(s"Is $muttsOrg readable by $currentUser? ${Readable(muttsOrg)}")
  println(s"Is $stevesOrg readable by $currentUser? ${Readable(stevesOrg)}")
     
  try {
    val result: String = steveAndJeffsGroup.readable {
      s"$currentUser can execute readable for $steveAndJeffsGroup!"
    }
    println(result)
  } catch {
    case e:UnauthorizedException =>
      println(s"$currentUser cannot execute readable for $steveAndJeffsGroup!")
  }
}
```
