//------------------------------------------------------------------------------
// <auto-generated>
//     Este código se generó a partir de una plantilla.
//
//     Los cambios manuales en este archivo pueden causar un comportamiento inesperado de la aplicación.
//     Los cambios manuales en este archivo se sobrescribirán si se regenera el código.
// </auto-generated>
//------------------------------------------------------------------------------

namespace MartinaPAS_MVC.Models
{
    using System;
    using System.Collections.Generic;
    
    public partial class Privilegios
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public Privilegios()
        {
            this.Rol_Privilegio = new HashSet<Rol_Privilegio>();
        }
    
        public int Id_Privilegio { get; set; }
        public string Nombre_Privilegio { get; set; }
    
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Rol_Privilegio> Rol_Privilegio { get; set; }
    }
}
