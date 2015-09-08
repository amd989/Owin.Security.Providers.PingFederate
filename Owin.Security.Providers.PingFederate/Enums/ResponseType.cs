using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin.Security.Providers.PingFederate.Enums
{
    public enum ResponseType
    {
        [PingFederate("code")]
        Code,
        [PingFederate("token")]
        Token
    }
}
