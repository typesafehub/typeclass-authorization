package com.typesafe.security.authorization

/**
 * A trait that defines a "readable" capability on an object.
 */
trait Readable[SO <: SecuredObject] extends SecurityOperation[SO]

/**
 * Provides convenience Readable methods on a secured object.
 */
object Readable {

  /**
   * Returns whether the secured object "so" is readable by the subject defined in "context".
   */
  def apply[SO <: SecuredObject](so: SO)(implicit ev: Readable[SO], context: SecurityContext): Boolean = {
    ev.apply(so, context)
  }
}
