/**
 * AUTO-GENERATED FILE — DO NOT EDIT MANUALLY
 *
 * This file should be regenerated using:
 *   supabase gen types typescript --project-id your-project-id > src/types/supabase.ts
 *
 * For now, this is a starter schema. Replace entirely with actual CLI output.
 */

export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  public: {
    Tables: {
      users: {
        Row: {
          id: string
          tg_id: number
          tg_username: string | null
          first_name: string
          last_name: string | null
          email: string | null
          phone: string | null
          role: 'owner' | 'realtor' | 'guest'
          language_code: string
          currency: string
          plan: 'free' | 'pro'
          notification_push: boolean | null
          notification_weekly: boolean | null
          notification_views: boolean | null
          created_at: string
          updated_at: string
        }
        Insert: Omit<Database['public']['Tables']['users']['Row'], 'id' | 'created_at' | 'updated_at'>
        Update: Partial<Database['public']['Tables']['users']['Insert']>
        Relationships: []
      }
      databases: {
        Row: {
          id: string
          owner_id: string
          name: string
          address: string | null
          type: 'business_center' | 'residential' | 'retail' | 'warehouse' | 'individual' | 'parking'
          color: string
          share_token: string
          share_expires_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: Omit<Database['public']['Tables']['databases']['Row'], 'id' | 'created_at' | 'updated_at'>
        Update: Partial<Database['public']['Tables']['databases']['Insert']>
        Relationships: [
          {
            foreignKeyName: 'databases_owner_id_fkey'
            columns: ['owner_id']
            referencedRelation: 'users'
            referencedColumns: ['id']
          }
        ]
      }
      properties: {
        Row: {
          id: string
          db_id: string
          owner_id: string
          name: string
          floor: string | null
          status: 'free' | 'occupied' | 'for_sale'
          area_useful: number | null
          area_total: number | null
          rent_type: 'per_m2' | 'fixed'
          rent_rate: number | null
          utilities_rate: number | null
          has_parking: boolean
          parking_spaces: number
          description: string | null
          address: string | null
          utilities: string[] | null
          sale_price: number | null
          tenant_name: string | null
          lease_start_date: string | null
          lease_end_date: string | null
          sort_order: number
          share_token: string
          share_expires_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: Omit<Database['public']['Tables']['properties']['Row'], 'id' | 'created_at' | 'updated_at'>
        Update: Partial<Database['public']['Tables']['properties']['Insert']>
        Relationships: [
          {
            foreignKeyName: 'properties_db_id_fkey'
            columns: ['db_id']
            referencedRelation: 'databases'
            referencedColumns: ['id']
          },
          {
            foreignKeyName: 'properties_owner_id_fkey'
            columns: ['owner_id']
            referencedRelation: 'users'
            referencedColumns: ['id']
          }
        ]
      }
      property_files: {
        Row: {
          id: string
          property_id: string
          owner_id: string
          storage_path: string
          file_name: string
          file_size: number
          mime_type: string
          sort_order: number
          created_at: string
        }
        Insert: Omit<Database['public']['Tables']['property_files']['Row'], 'id' | 'created_at'>
        Update: Partial<Database['public']['Tables']['property_files']['Insert']>
        Relationships: [
          {
            foreignKeyName: 'property_files_property_id_fkey'
            columns: ['property_id']
            referencedRelation: 'properties'
            referencedColumns: ['id']
          },
          {
            foreignKeyName: 'property_files_owner_id_fkey'
            columns: ['owner_id']
            referencedRelation: 'users'
            referencedColumns: ['id']
          }
        ]
      }
      collections: {
        Row: {
          id: string
          realtor_id: string
          name: string
          is_draft: boolean
          share_token: string
          share_expires_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: Omit<Database['public']['Tables']['collections']['Row'], 'id' | 'created_at' | 'updated_at'>
        Update: Partial<Database['public']['Tables']['collections']['Insert']>
        Relationships: [
          {
            foreignKeyName: 'collections_realtor_id_fkey'
            columns: ['realtor_id']
            referencedRelation: 'users'
            referencedColumns: ['id']
          }
        ]
      }
      realtor_subscriptions: {
        Row: {
          id: string
          realtor_id: string
          db_id: string
          created_at: string
        }
        Insert: Omit<Database['public']['Tables']['realtor_subscriptions']['Row'], 'id' | 'created_at'>
        Update: Partial<Database['public']['Tables']['realtor_subscriptions']['Insert']>
        Relationships: [
          {
            foreignKeyName: 'realtor_subscriptions_realtor_id_fkey'
            columns: ['realtor_id']
            referencedRelation: 'users'
            referencedColumns: ['id']
          },
          {
            foreignKeyName: 'realtor_subscriptions_db_id_fkey'
            columns: ['db_id']
            referencedRelation: 'databases'
            referencedColumns: ['id']
          }
        ]
      }
      notifications: {
        Row: {
          id: string
          user_id: string
          type: string
          title: string
          body: string | null
          is_read: boolean
          data: Json | null
          created_at: string
        }
        Insert: Omit<Database['public']['Tables']['notifications']['Row'], 'id' | 'created_at'>
        Update: Partial<Database['public']['Tables']['notifications']['Insert']>
        Relationships: [
          {
            foreignKeyName: 'notifications_user_id_fkey'
            columns: ['user_id']
            referencedRelation: 'users'
            referencedColumns: ['id']
          }
        ]
      }
      rent_payments: {
        Row: {
          id: string
          property_id: string
          owner_id: string
          due_day: number
          notify_days_before: number
          is_active: boolean
          created_at: string
          updated_at: string
        }
        Insert: Omit<Database['public']['Tables']['rent_payments']['Row'], 'id' | 'created_at' | 'updated_at'>
        Update: Partial<Database['public']['Tables']['rent_payments']['Insert']>
        Relationships: [
          {
            foreignKeyName: 'rent_payments_property_id_fkey'
            columns: ['property_id']
            referencedRelation: 'properties'
            referencedColumns: ['id']
          },
          {
            foreignKeyName: 'rent_payments_owner_id_fkey'
            columns: ['owner_id']
            referencedRelation: 'users'
            referencedColumns: ['id']
          }
        ]
      }
      rent_payment_records: {
        Row: {
          id: string
          property_id: string
          owner_id: string
          due_date: string
          paid_at: string | null
          amount: number | null
          status: 'pending' | 'paid' | 'overdue'
          notes: string | null
          created_at: string
          updated_at: string
        }
        Insert: Omit<Database['public']['Tables']['rent_payment_records']['Row'], 'id' | 'created_at' | 'updated_at'>
        Update: Partial<Database['public']['Tables']['rent_payment_records']['Insert']>
        Relationships: [
          {
            foreignKeyName: 'rent_payment_records_property_id_fkey'
            columns: ['property_id']
            referencedRelation: 'properties'
            referencedColumns: ['id']
          },
          {
            foreignKeyName: 'rent_payment_records_owner_id_fkey'
            columns: ['owner_id']
            referencedRelation: 'users'
            referencedColumns: ['id']
          }
        ]
      }
      property_views: {
        Row: {
          id: string
          property_id: string
          viewer_id: string | null
          viewer_name: string | null
          action: 'view' | 'photo' | 'document' | 'share' | 'favorite'
          created_at: string
        }
        Insert: Omit<Database['public']['Tables']['property_views']['Row'], 'id' | 'created_at'>
        Update: Partial<Database['public']['Tables']['property_views']['Insert']>
        Relationships: [
          {
            foreignKeyName: 'property_views_property_id_fkey'
            columns: ['property_id']
            referencedRelation: 'properties'
            referencedColumns: ['id']
          }
        ]
      }
      rate_limits: {
        Row: {
          ip: string
          count: number
          reset_at: string
        }
        Insert: Database['public']['Tables']['rate_limits']['Row']
        Update: Partial<Database['public']['Tables']['rate_limits']['Insert']>
        Relationships: []
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      current_app_user_id: {
        Args: Record<PropertyKey, never>
        Returns: string | null
      }
      claim_guest_link: {
        Args: { p_token: string }
        Returns: {
          property_id: string | null
          db_id: string | null
          error: string | null
        } | null
      }
      lookup_shared_property: {
        Args: { p_token: string }
        Returns: {
          id: string
          db_id: string
        }[]
      }
      lookup_shared_collection: {
        Args: { p_token: string }
        Returns: {
          id: string
          realtor_id: string
        }[]
      }
      lookup_shared_db: {
        Args: { p_token: string }
        Returns: {
          id: string
          owner_id: string
          share_expires_at: string | null
        }[]
      }
    }
    Enums: {
      [_ in never]: never
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

export type Tables<
  PublicTableNameOrOptions extends
    | keyof (Database['public']['Tables'] & Database['public']['Views'])
    | { schema: keyof Database },
  TableName extends PublicTableNameOrOptions extends { schema: keyof Database }
    ? keyof (Database[PublicTableNameOrOptions['schema']]['Tables'] &
        Database[PublicTableNameOrOptions['schema']]['Views'])
    : never = never
> = PublicTableNameOrOptions extends { schema: keyof Database }
  ? (Database[PublicTableNameOrOptions['schema']]['Tables'] &
      Database[PublicTableNameOrOptions['schema']]['Views'])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : PublicTableNameOrOptions extends keyof (Database['public']['Tables'] &
        Database['public']['Views'])
    ? (Database['public']['Tables'] &
        Database['public']['Views'])[PublicTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  PublicTableNameOrOptions extends
    | keyof Database['public']['Tables']
    | { schema: keyof Database },
  TableName extends PublicTableNameOrOptions extends { schema: keyof Database }
    ? keyof Database[PublicTableNameOrOptions['schema']]['Tables']
    : never = never
> = PublicTableNameOrOptions extends { schema: keyof Database }
  ? Database[PublicTableNameOrOptions['schema']]['Tables'][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : PublicTableNameOrOptions extends keyof Database['public']['Tables']
    ? Database['public']['Tables'][PublicTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  PublicTableNameOrOptions extends
    | keyof Database['public']['Tables']
    | { schema: keyof Database },
  TableName extends PublicTableNameOrOptions extends { schema: keyof Database }
    ? keyof Database[PublicTableNameOrOptions['schema']]['Tables']
    : never = never
> = PublicTableNameOrOptions extends { schema: keyof Database }
  ? Database[PublicTableNameOrOptions['schema']]['Tables'][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : PublicTableNameOrOptions extends keyof Database['public']['Tables']
    ? Database['public']['Tables'][PublicTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never
