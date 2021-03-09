using System;
using System.Collections.Generic;
using System.Text;

namespace Projektarbete_IT_säkerhet
{
    class Vault
    {
        public Dictionary<string, string> Pwds;

        public void AddPwd(string key, string newpwd)
        {
            Pwds.Add(key, newpwd);
        }
    }
}
