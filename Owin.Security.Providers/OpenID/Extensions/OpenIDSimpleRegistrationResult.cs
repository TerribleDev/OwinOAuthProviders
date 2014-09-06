using System;
using System.Collections.Generic;
using System.Linq;

namespace Owin.Security.Providers.OpenID.Extensions
{
    /// <summary>
    /// Contains values of OpenID Simple Registration Extension fields.
    /// </summary>
    public class OpenIDSimpleRegistrationResult
    {

        public IDictionary<OpenIDSimpleRegistrationField, string> Values { get; set; }


        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIDSimpleRegistrationResult"/> class.
        /// </summary>
        public OpenIDSimpleRegistrationResult()
        {
            Values = new Dictionary<OpenIDSimpleRegistrationField, string>();
        }

        /// <summary>
        /// Gets the SREG field value.
        /// </summary>
        public string GetFieldValue(OpenIDSimpleRegistrationField field)
        {
            if (!Values.ContainsKey(field)) return null;
            return Values[field];
        }

    }
}