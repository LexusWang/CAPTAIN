def memory_protection(permission: int):
    '''
    This function is used to transfer the an integer to a permission set,
    which can be used when parsing some CDM format data.
    
    Args:
        A permission integer.
        
    Return:
        A list containing the permission tags.
    '''
    
    if permission < 0 or permission > 7:
        raise ValueError("Invalid permission!!!")
    else:
        if permission == 0:
            return ['PROT_NONE']
        elif permission == 1:
            return ['PROT_EXEC']
        elif permission == 2:
            return ['PROT_WRITE']
        elif permission == 3:
            return ['PROT_WRITE', 'PROT_EXEC']
        elif permission == 4:
            return ['PROT_READ']
        elif permission == 5:
            return ['PROT_READ', 'PROT_EXEC']
        elif permission == 6:
            return ['PROT_READ', 'PROT_WRITE']
        elif permission == 7:
            return ['PROT_READ', 'PROT_WRITE', 'PROT_EXEC']