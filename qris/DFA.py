from enum import Enum

'''
Definition of DFA that accept query size increments.
'''

class H1_EN_DFA(Enum):
    NUL = 'Nul'
    L = 'Ltr'
    Dp = 'Spa(%)'
    L_L = 1
    L_Dp = 3
    Dp_L = 1

class H1_ZH_DFA(Enum):
    NUL = 'Nul'
    L = 'Ltr'
    D = 'Apo+Ltr'
    Dp = 'Apo(%)+Ltr'
    L_L = 1
    L_D = 2
    L_Dp = 4
    D_L = 1
    D_D = 2
    Dp_L = 1
    Dp_Dp = 4

class H2_EN_DFA(Enum):
    NUL = 'Nul'
    L = 'Ltr'
    L0 = 'Ltr(0)'
    Dp = 'Spa(%)'
    L_L = 1
    L_L0 = 0
    L_Dp = 2
    L0_L = 1
    L0_Dp = 2
    Dp_L = 1
    Dp_L0 = 0

class H2_ZH_DFA(Enum):
    NUL = 'Nul'
    L = 'Ltr'
    L0 = 'Ltr(0)'
    Dx = 'Apo/Apo(%)+Ltr'
    L_L = 1
    L_L0 = 0
    L_Dx = (2, 3)
    L0_L = 1
    L0_Dx = (2, 3)
    Dx_L = 1
    Dx_L0 = 0
    Dx_Dx = (2, 3)


def H1_EN_DFA_TF(d_size, state, enc):
    '''
    DFA transfer function for HTTP/1.1 English query.
    '''
    if state == H1_EN_DFA.L.value:
        # L -> L
        if d_size == H1_EN_DFA.L_L.value:
            return H1_EN_DFA.L.value
        # L -> Dp
        if d_size == H1_EN_DFA.L_Dp.value and enc == True:
            return H1_EN_DFA.Dp.value
    
    elif state == H1_EN_DFA.Dp.value:
        # Dp -> L
        if d_size == H1_EN_DFA.Dp_L.value:
            return H1_EN_DFA.L.value
    
    return H1_EN_DFA.NUL.value


def H1_ZH_DFA_TF(d_size, state, enc):
    '''
    DFA transfer function for HTTP/1.1 Chinese query.
    '''
    if state == H1_ZH_DFA.L.value:
        # L -> L
        if d_size == H1_ZH_DFA.L_L.value:
            return H1_ZH_DFA.L.value
        # L -> D
        if d_size == H1_ZH_DFA.L_D.value and enc == False:
            return H1_ZH_DFA.D.value
        # L -> Dp
        if d_size == H1_ZH_DFA.L_Dp.value and enc == True:
            return H1_ZH_DFA.Dp.value

    elif state == H1_ZH_DFA.D.value:
        # D -> L
        if d_size == H1_ZH_DFA.D_L.value:
            return H1_ZH_DFA.L.value
        # D -> D
        if d_size == H1_ZH_DFA.D_D.value:
            return H1_ZH_DFA.D.value

    elif state == H1_ZH_DFA.Dp.value:
        # Dp -> L
        if d_size == H1_ZH_DFA.Dp_L.value:
            return H1_ZH_DFA.L.value
        # Dp -> Dp
        if d_size == H1_ZH_DFA.Dp_Dp.value:
            return H1_ZH_DFA.Dp.value
    
    return H1_ZH_DFA.NUL.value


def H2_EN_DFA_TF(d_size, state, enc):
    '''
    DFA transfer function for HTTP/2 English query.
    '''
    if state == H2_EN_DFA.L.value:
        # L -> L
        if d_size == H2_EN_DFA.L_L.value:
            return H2_EN_DFA.L.value
        # L -> L0
        if d_size == H2_EN_DFA.L_L0.value:
            return H2_EN_DFA.L0.value
        # L -> Dp
        if d_size == H2_EN_DFA.L_Dp.value and enc == True:
            return H2_EN_DFA.Dp.value
    
    elif state == H2_EN_DFA.L0.value:
        # L0 -> L
        if d_size == H2_EN_DFA.L0_L.value:
            return H2_EN_DFA.L.value
        # L0 -> Dp
        if d_size == H2_EN_DFA.L0_Dp.value and enc == True:
            return H2_EN_DFA.Dp.value

    elif state == H2_EN_DFA.Dp.value:
        # Dp -> L
        if d_size == H2_EN_DFA.Dp_L.value:
            return H2_EN_DFA.L.value
        # Dp -> L0
        if d_size == H2_EN_DFA.Dp_L0.value:
            return H2_EN_DFA.L0.value
    
    return H2_EN_DFA.NUL.value


def H2_ZH_DFA_TF(d_size, state, enc):
    '''
    DFA transfer function for HTTP/2 Chinese query.
    '''
    if state == H2_ZH_DFA.L.value:
        # L -> L
        if d_size == H2_ZH_DFA.L_L.value:
            return H2_ZH_DFA.L.value
        # L -> L0
        if d_size == H2_ZH_DFA.L_L0.value:
            return H2_ZH_DFA.L0.value
        # L -> Dx
        if d_size in list(H2_ZH_DFA.L_Dx.value):
            return H2_ZH_DFA.Dx.value
    
    elif state == H2_ZH_DFA.L0.value:
        # L0 -> L
        if d_size == H2_ZH_DFA.L0_L.value:
            return H2_ZH_DFA.L.value
        # L0 -> Dx
        if d_size in list(H2_ZH_DFA.L0_Dx.value):
            return H2_ZH_DFA.Dx.value
    
    elif state == H2_ZH_DFA.Dx.value:
        # Dx -> L
        if d_size == H2_ZH_DFA.Dx_L.value:
            return H2_ZH_DFA.L.value
        # Dx -> L0
        if d_size == H2_ZH_DFA.Dx_L0.value:
            return H2_ZH_DFA.L0.value
        # Dx -> Dx
        if d_size in list(H2_ZH_DFA.Dx_Dx.value):
            return H2_ZH_DFA.Dx.value
    
    return H2_ZH_DFA.NUL.value
