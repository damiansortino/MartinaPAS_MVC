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
    
    public partial class Endosos
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public Endosos()
        {
            this.Cuotas = new HashSet<Cuotas>();
        }
    
        public int id { get; set; }
        public int idpoliza { get; set; }
        public int endoso { get; set; }
        public Nullable<int> suplemento { get; set; }
        public Nullable<System.DateTime> fechavigenciadesde { get; set; }
        public Nullable<System.DateTime> fechavigenciahasta { get; set; }
        public int cantidadcuotas { get; set; }
        public int idbien { get; set; }
        public string asociada { get; set; }
    
        public virtual Bienes Bienes { get; set; }
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Cuotas> Cuotas { get; set; }
        public virtual Polizas Polizas { get; set; }
    }
}
