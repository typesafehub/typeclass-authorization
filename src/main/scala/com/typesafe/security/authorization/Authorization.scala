package com.typesafe.security.authorization

trait Subject {

}

trait SecuredObject {

}

trait SecurityContext {

  def subject: Subject

  def ability: Ability

  def isAuthorized(activity: Activity, securedObject: SecuredObject): Boolean = {
    relevantRules(activity, subject, securedObject).exists { (rule: Rule) =>
      rule.matchesCondition(activity, subject, securedObject)
    }
  }

  def relevantRules(activity: Activity, subject: Subject, securedObject: SecuredObject): Set[Rule] = {
    // Return only the rules which are relevant for the type of secured object.
    ability.rules.filter { rule =>
      val sameActivity = rule.activity.equals(activity)
      val isAssignableFrom = rule.typeClass.isAssignableFrom(securedObject.getClass)
      sameActivity && isAssignableFrom
    }
  }
}

class Rule(val typeClass: Class[_ <: SecuredObject], val activity: Activity, block: (Subject, SecuredObject) => Boolean) {
  def matchesCondition(activity: Activity, subject: Subject, securedObject: SecuredObject): Boolean = {
    block(subject, securedObject)
  }
}

trait Ability {

  def rules: Set[Rule]

}

trait AuthorizationMethods {

  def authorize[T](activity: Activity, securedObject: SecuredObject, block: => T)(implicit ctx: SecurityContext) = {
    if (!isAuthorized(activity, securedObject)) {
      throw new OperationNotAuthorizedException("Not authorized!")
    }
    block
  }

  def isAuthorized(activity: Activity, securedObject: SecuredObject)(implicit ctx: SecurityContext): Boolean = {
    ctx.isAuthorized(activity, securedObject)
  }

}

trait Activity

object Activities {

  case object CanManage extends Activity

  case object CanRead extends Activity

  case object CanDelete extends Activity

}

class OperationNotAuthorizedException(message: String) extends Exception(message)
