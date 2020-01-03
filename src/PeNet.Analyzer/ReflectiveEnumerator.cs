using System;
using System.Collections.Generic;
using System.Linq;

namespace PeNet.Analyzer
{
    internal static class ReflectiveEnumerator
    {
        public static IEnumerable<T> GetEnumerableOfType<T>(params object[] constructorArgs) where T : class
        {
            var types = typeof(T)
                .Assembly.GetTypes()
                .Where(t => t.IsSubclassOf(typeof(T)) && !t.IsAbstract)
                .Select(t => (T)Activator.CreateInstance(t, constructorArgs));

            return types;
        }
    }
}