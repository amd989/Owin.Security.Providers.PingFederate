using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System;
using System.Collections.Concurrent;

namespace Owin.Security.Providers.PingFederate.Enums
{

    internal class PingFederateAttribute : Attribute
    {
        internal PingFederateAttribute(string pingFederateName)
        {
            this.PingFederateName = pingFederateName;
        }
        public string PingFederateName { get; private set; }
    }


    public static class EnumExtensions
    {
        private static readonly ConcurrentDictionary<Type, ConcurrentDictionary<Type, Attribute>> _enumCache = new ConcurrentDictionary<Type, ConcurrentDictionary<Type, Attribute>>();



        public static string PingFederateName(this Enum enumVal)
        {
            return GetAttributeInternal<PingFederateAttribute>(enumVal).PingFederateName;
        }

        public static TAttribute GetAttribute<TAttribute>(this Enum enumVal)
            where TAttribute : Attribute
        {
            return GetAttributeInternal<TAttribute>(enumVal);
        }

        private static TAttribute GetAttributeInternal<TAttribute>(Enum value)
            where TAttribute : Attribute
        {
            Type enumType = value.GetType();
            Type attributeType = typeof(TAttribute);

            var savedEnum = _enumCache.GetOrAdd(enumType, new ConcurrentDictionary<Type, Attribute>());
            var attribute = savedEnum.GetOrAdd(attributeType,
                new Lazy<TAttribute>(() => GetAttributeInternal<TAttribute>(enumType, attributeType, value)).Value);
            return (TAttribute)attribute;
        }

        private static TAttribute GetAttributeInternal<TAttribute>(Type enumType, Type attributeType, Enum value)
            where TAttribute : Attribute
        {
            TAttribute[] attributeArray = enumType.GetField(Enum.GetName(enumType, value)).GetCustomAttributes(attributeType, false) as TAttribute[];
            if (attributeArray == null || attributeArray.Length == 0)
                return default(TAttribute);
            return attributeArray[0];
        }
    }
}
