using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ApiMkm.Configuration
{
    public class MkmAuthTokenSection : ConfigurationSection
    {
        [ConfigurationProperty("appToken", IsRequired = true)]
        public string AppToken
        {
            get { return (string)this["appToken"]; }

        }

        [ConfigurationProperty("appSecret", IsRequired = true)]
        public string AppSecret
        {
            get { return (string)this["appSecret"]; }

        }
        [ConfigurationProperty("accessToken", IsRequired = true)]
        public string AccessToken
        {
            get { return (string)this["accessToken"]; }

        }
        [ConfigurationProperty("accessSecret", IsRequired = true)]
        public string AccessSecret
        {
            get { return (string)this["accessSecret"]; }

        }
    }
}
